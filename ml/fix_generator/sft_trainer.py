"""
Fix Generator: SFT + RLHF pipeline for automated vulnerability patching.

Uses StarCoderBase-1B fine-tuned with:
  Stage 1: Supervised Fine-Tuning (SFT) on (vulnerable_code, fix) pairs
  Stage 2: RLHF via DPO (Direct Preference Optimization) using fix quality preferences

StarCoderBase-1B is chosen because:
  - 1B parameters → fits on M1 Pro 16GB (with 4-bit QLoRA)
  - Pretrained on 80+ languages including Python and JavaScript
  - Better code quality than CodeT5+ for generation tasks
  - Can be trained for FREE on Kaggle (30h/week) or Google Colab

For free GPU training:
  - QLoRA (4-bit) reduces memory to ~4GB → runs on any free GPU
  - Kaggle T4 (16GB): batch_size=4, gradient_accumulation=8
  - Google Colab T4 (16GB): same settings
"""
from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import torch
from loguru import logger


# ──────────────────────────────────────────────
# Training Config
# ──────────────────────────────────────────────

@dataclass
class SFTConfig:
    """Configuration for Supervised Fine-Tuning of the fix generator."""
    base_model: str = "bigcode/starcoderbase-1b"
    checkpoint_dir: Path = Path("checkpoints/fix_generator")
    data_path: Path = Path("data/processed/vuln_pairs")

    # QLoRA config (4-bit quantization + LoRA adapters)
    use_qlora: bool = True
    lora_r: int = 16               # LoRA rank
    lora_alpha: int = 32           # LoRA scaling factor
    lora_dropout: float = 0.05
    lora_target_modules: list[str] = field(default_factory=lambda: [
        "q_proj", "k_proj", "v_proj", "o_proj",
        "gate_proj", "up_proj", "down_proj"
    ])

    # Training hyperparameters
    max_seq_length: int = 1024     # input + output tokens
    batch_size: int = 2            # per device (for M1 Pro)
    gradient_accumulation_steps: int = 16   # effective batch = 2*16 = 32
    num_epochs: int = 3
    learning_rate: float = 2e-4
    warmup_ratio: float = 0.05
    weight_decay: float = 0.01
    max_grad_norm: float = 1.0

    # Generation settings
    max_new_tokens: int = 512
    temperature: float = 0.2
    top_p: float = 0.95
    do_sample: bool = True

    # Device
    device: str = "auto"


# ──────────────────────────────────────────────
# Prompt Templates
# ──────────────────────────────────────────────

FIX_GENERATOR_SYSTEM_PROMPT = """You are SecureAI, an expert security engineer and code fixer.
Your task is to analyze vulnerable code, understand the security issue, and produce a fixed version.

Rules:
1. Only change what is necessary to fix the vulnerability
2. Preserve the original function's behavior and signature
3. Add a brief comment explaining what you changed and why
4. Do not introduce new dependencies unless absolutely necessary
5. Follow the same coding style as the original code"""


def build_fix_prompt(
    language: str,
    cwe_id: str,
    severity: str,
    vulnerable_code: str,
    taint_path: str = "",
    fix_description: str = "",
) -> str:
    """Build the instruction prompt for the fix generator."""
    return f"""<|system|>
{FIX_GENERATOR_SYSTEM_PROMPT}
<|end|>
<|user|>
Fix the following {language} code that contains a **{cwe_id}** vulnerability (Severity: {severity}).

{f'Vulnerability detail: {fix_description}' if fix_description else ''}
{f'Taint path: {taint_path}' if taint_path else ''}

**Vulnerable Code:**
```{language}
{vulnerable_code}
```

Provide the complete fixed code with inline comments explaining the security changes.
<|end|>
<|assistant|>
```{language}
"""


def build_fix_response(fixed_code: str) -> str:
    """Build the expected response (target) for SFT training."""
    return f"{fixed_code}\n```\n<|end|>"


# ──────────────────────────────────────────────
# Dataset
# ──────────────────────────────────────────────

class FixGeneratorDataset(torch.utils.data.Dataset):
    """
    Dataset for SFT training of the fix generator.

    Each sample is a full text sequence:
    [PROMPT] + [FIXED_CODE] (teacher forcing)

    The model learns to complete the prompt with the correct fix.
    Loss is computed only on the completion part (not the prompt).
    """

    def __init__(
        self,
        data_path: Path,
        tokenizer: Any,
        max_seq_length: int = 1024,
    ) -> None:
        import json
        self.tokenizer = tokenizer
        self.max_seq_length = max_seq_length
        self.samples: list[dict] = []

        if data_path.exists():
            with open(data_path) as f:
                for line in f:
                    try:
                        self.samples.append(json.loads(line.strip()))
                    except json.JSONDecodeError:
                        continue

        logger.info(f"FixGeneratorDataset: {len(self.samples)} samples from {data_path}")

    def __len__(self) -> int:
        return len(self.samples)

    def __getitem__(self, idx: int) -> dict[str, torch.Tensor]:
        sample = self.samples[idx]

        prompt = build_fix_prompt(
            language=sample.get("language", "python"),
            cwe_id=sample.get("cwe_id", "UNKNOWN"),
            severity=sample.get("severity", "HIGH"),
            vulnerable_code=sample["vulnerable_code"],
            taint_path=sample.get("taint_path", ""),
            fix_description=sample.get("fix_description", ""),
        )
        response = build_fix_response(sample["fixed_code"])
        full_text = prompt + response

        # Tokenize full text
        tokenized = self.tokenizer(
            full_text,
            max_length=self.max_seq_length,
            truncation=True,
            padding="max_length",
            return_tensors="pt",
        )

        input_ids = tokenized["input_ids"].squeeze(0)
        attention_mask = tokenized["attention_mask"].squeeze(0)

        # Labels: mask out the prompt tokens (-100 = ignored in cross-entropy)
        prompt_tokenized = self.tokenizer(
            prompt,
            max_length=self.max_seq_length,
            truncation=True,
            return_tensors="pt",
        )
        prompt_len = prompt_tokenized["input_ids"].size(1)

        labels = input_ids.clone()
        labels[:prompt_len] = -100  # Don't compute loss on prompt tokens

        return {
            "input_ids": input_ids,
            "attention_mask": attention_mask,
            "labels": labels,
        }


# ──────────────────────────────────────────────
# SFT Trainer
# ──────────────────────────────────────────────

class FixGeneratorSFTTrainer:
    """
    Supervised Fine-Tuning trainer for the fix generator model.

    Uses QLoRA (4-bit quantization + LoRA adapters) for memory efficiency:
    - Full model: ~2GB in 4-bit
    - LoRA adapters: ~50MB additional
    - Total: ~2.5GB → runs on any free GPU tier

    After SFT, use DPO for RLHF-style preference learning.
    """

    def __init__(self, config: SFTConfig) -> None:
        self.config = config
        self.device = self._select_device(config.device)
        logger.info(f"SFT Trainer initialized on: {self.device}")

    def _select_device(self, device: str) -> str:
        if device == "auto":
            if torch.cuda.is_available():
                return "cuda"
            elif hasattr(torch.backends, "mps") and torch.backends.mps.is_available():
                return "mps"
            return "cpu"
        return device

    def setup_model_and_tokenizer(self) -> tuple[Any, Any]:
        """Load model with QLoRA quantization and LoRA adapters."""
        from transformers import AutoModelForCausalLM, AutoTokenizer, BitsAndBytesConfig
        from peft import get_peft_model, LoraConfig, TaskType, prepare_model_for_kbit_training

        logger.info(f"Loading tokenizer: {self.config.base_model}")
        tokenizer = AutoTokenizer.from_pretrained(self.config.base_model)
        if tokenizer.pad_token is None:
            tokenizer.pad_token = tokenizer.eos_token

        if self.config.use_qlora and self.device == "cuda":
            logger.info("Loading model in 4-bit QLoRA mode (CUDA)")
            bnb_config = BitsAndBytesConfig(
                load_in_4bit=True,
                bnb_4bit_use_double_quant=True,
                bnb_4bit_quant_type="nf4",
                bnb_4bit_compute_dtype=torch.bfloat16,
            )
            model = AutoModelForCausalLM.from_pretrained(
                self.config.base_model,
                quantization_config=bnb_config,
                device_map="auto",
                trust_remote_code=True,
            )
            model = prepare_model_for_kbit_training(model)
        else:
            logger.info(f"Loading model in float16 mode ({self.device})")
            model = AutoModelForCausalLM.from_pretrained(
                self.config.base_model,
                torch_dtype=torch.float16,
                trust_remote_code=True,
            ).to(self.device)

        # Apply LoRA adapters
        lora_config = LoraConfig(
            task_type=TaskType.CAUSAL_LM,
            r=self.config.lora_r,
            lora_alpha=self.config.lora_alpha,
            lora_dropout=self.config.lora_dropout,
            target_modules=self.config.lora_target_modules,
            bias="none",
        )
        model = get_peft_model(model, lora_config)
        model.print_trainable_parameters()

        return model, tokenizer

    def train(self) -> None:
        """
        Run the SFT training loop using HuggingFace Trainer.
        """
        from transformers import TrainingArguments, Trainer, DataCollatorForSeq2Seq

        model, tokenizer = self.setup_model_and_tokenizer()

        train_ds = FixGeneratorDataset(
            self.config.data_path / "train.jsonl",
            tokenizer,
            self.config.max_seq_length,
        )
        val_ds = FixGeneratorDataset(
            self.config.data_path / "val.jsonl",
            tokenizer,
            self.config.max_seq_length,
        )

        training_args = TrainingArguments(
            output_dir=str(self.config.checkpoint_dir),
            num_train_epochs=self.config.num_epochs,
            per_device_train_batch_size=self.config.batch_size,
            per_device_eval_batch_size=self.config.batch_size,
            gradient_accumulation_steps=self.config.gradient_accumulation_steps,
            learning_rate=self.config.learning_rate,
            warmup_ratio=self.config.warmup_ratio,
            weight_decay=self.config.weight_decay,
            max_grad_norm=self.config.max_grad_norm,
            evaluation_strategy="steps",
            eval_steps=200,
            save_strategy="steps",
            save_steps=200,
            save_total_limit=3,
            load_best_model_at_end=True,
            metric_for_best_model="eval_loss",
            logging_steps=50,
            fp16=self.device == "cuda",
            report_to="mlflow",
            run_name="fix_generator_sft",
            dataloader_num_workers=2,
            optim="adamw_torch",
            lr_scheduler_type="cosine",
        )

        trainer = Trainer(
            model=model,
            args=training_args,
            train_dataset=train_ds,
            eval_dataset=val_ds,
            tokenizer=tokenizer,
        )

        logger.info("Starting SFT training...")
        trainer.train()
        trainer.save_model(str(self.config.checkpoint_dir / "final"))
        logger.info(f"Model saved to {self.config.checkpoint_dir / 'final'}")


# ──────────────────────────────────────────────
# Inference
# ──────────────────────────────────────────────

class FixGenerator:
    """
    Inference interface for the trained fix generator model.

    Usage:
        generator = FixGenerator.from_checkpoint("checkpoints/fix_generator/final")
        fix = generator.generate_fix(
            language="python",
            cwe_id="CWE-89",
            severity="CRITICAL",
            vulnerable_code="...",
        )
    """

    def __init__(self, model: Any, tokenizer: Any, config: SFTConfig) -> None:
        self.model = model
        self.tokenizer = tokenizer
        self.config = config

    @classmethod
    def from_checkpoint(
        cls, checkpoint_path: str, config: SFTConfig | None = None
    ) -> "FixGenerator":
        from transformers import AutoModelForCausalLM, AutoTokenizer
        from peft import PeftModel

        config = config or SFTConfig()
        tokenizer = AutoTokenizer.from_pretrained(checkpoint_path)
        base_model = AutoModelForCausalLM.from_pretrained(
            config.base_model, torch_dtype=torch.float16, trust_remote_code=True
        )
        model = PeftModel.from_pretrained(base_model, checkpoint_path)
        model.eval()
        return cls(model, tokenizer, config)

    def generate_fix(
        self,
        language: str,
        cwe_id: str,
        severity: str,
        vulnerable_code: str,
        taint_path: str = "",
        fix_description: str = "",
        num_candidates: int = 3,
    ) -> list[str]:
        """
        Generate N candidate fixes for a vulnerable code snippet.

        Args:
            language: Programming language (python/javascript)
            cwe_id: CWE identifier (e.g., "CWE-89")
            severity: CRITICAL/HIGH/MEDIUM/LOW
            vulnerable_code: The vulnerable source code
            taint_path: Optional taint path description
            fix_description: Optional human-readable vuln description
            num_candidates: Number of fix candidates to generate

        Returns:
            List of candidate fix strings (best first)
        """
        prompt = build_fix_prompt(
            language=language,
            cwe_id=cwe_id,
            severity=severity,
            vulnerable_code=vulnerable_code,
            taint_path=taint_path,
            fix_description=fix_description,
        )

        inputs = self.tokenizer(prompt, return_tensors="pt")

        candidates = []
        for _ in range(num_candidates):
            with torch.no_grad():
                outputs = self.model.generate(
                    **inputs,
                    max_new_tokens=self.config.max_new_tokens,
                    temperature=self.config.temperature,
                    top_p=self.config.top_p,
                    do_sample=self.config.do_sample,
                    pad_token_id=self.tokenizer.eos_token_id,
                )
            # Decode only the generated part
            generated = outputs[0][inputs["input_ids"].size(1):]
            fix_text = self.tokenizer.decode(generated, skip_special_tokens=True)

            # Extract code block
            if "```" in fix_text:
                fix_text = fix_text.split("```")[0].strip()
            candidates.append(fix_text)

        return candidates


# ──────────────────────────────────────────────
# Entry Point
# ──────────────────────────────────────────────

if __name__ == "__main__":
    import argparse
    p = argparse.ArgumentParser(description="Train SecureAI fix generator (SFT)")
    p.add_argument("--base-model", default="bigcode/starcoderbase-1b")
    p.add_argument("--data-path", type=Path, default=Path("data/processed/vuln_pairs"))
    p.add_argument("--checkpoint-dir", type=Path, default=Path("checkpoints/fix_generator"))
    p.add_argument("--epochs", type=int, default=3)
    p.add_argument("--batch-size", type=int, default=2)
    p.add_argument("--no-qlora", action="store_true")
    args = p.parse_args()

    config = SFTConfig(
        base_model=args.base_model,
        data_path=args.data_path,
        checkpoint_dir=args.checkpoint_dir,
        num_epochs=args.epochs,
        batch_size=args.batch_size,
        use_qlora=not args.no_qlora,
    )

    trainer = FixGeneratorSFTTrainer(config)
    trainer.train()
