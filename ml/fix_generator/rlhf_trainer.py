"""
RLHF Trainer for the Fix Generator (DPO Method).

Direct Preference Optimization (DPO) is used to align the fix generator
with security best practices and syntactical correctness, without needing
a separate reward model during training.

We use a dataset of preference pairs: (prompt, chosen_fix, rejected_fix).
- chosen_fix: Correctly fixes the vulnerability and passes tests.
- rejected_fix: Either introduces a syntax error, fails to remove the taint path, or is functionally incorrect.
"""
from __future__ import annotations

import torch
from pathlib import Path
from dataclasses import dataclass
from loguru import logger

try:
    from trl import DPOTrainer, DPOConfig
except ImportError:
    DPOTrainer = None
    DPOConfig = None


@dataclass
class RLHFConfig:
    sft_model_path: str = "checkpoints/fix_generator/final"
    output_dir: Path = Path("checkpoints/fix_generator/rlhf")
    data_path: Path = Path("data/processed/rlhf_pairs.jsonl")
    
    batch_size: int = 1
    gradient_accumulation_steps: int = 16
    learning_rate: float = 5e-6
    epochs: int = 2
    beta: float = 0.1  # KL penalty


def train_dpo(config: RLHFConfig):
    """
    Trains the fix generator using DPO.
    """
    if DPOTrainer is None:
        logger.error("trl library is required for RLHF training. Run: pip install trl")
        return

    from transformers import AutoModelForCausalLM, AutoTokenizer
    from peft import PeftModel, LoraConfig
    from datasets import load_dataset

    logger.info("Loading SFT model for DPO...")
    tokenizer = AutoTokenizer.from_pretrained(config.sft_model_path)
    
    # We load the base model and the SFT adapter as the starting point.
    # In DPO, we need a reference model (the SFT model) and an active model.
    # trl handles creating the reference model automatically if we pass a PeftModel.
    model = AutoModelForCausalLM.from_pretrained(
        "bigcode/starcoderbase-1b", 
        load_in_4bit=True,
        device_map="auto"
    )
    # Wrap with LoRA for training
    lora_config = LoraConfig(
        r=16,
        lora_alpha=32,
        lora_dropout=0.05,
        target_modules=["q_proj", "k_proj", "v_proj", "o_proj"],
        bias="none",
        task_type="CAUSAL_LM",
    )
    
    logger.info(f"Loading preference dataset from {config.data_path}...")
    # Dataset should have columns: 'prompt', 'chosen', 'rejected'
    try:
        dataset = load_dataset("json", data_files=str(config.data_path), split="train")
    except Exception as e:
        logger.error(f"Failed to load dataset: {e}")
        return

    # Split into train/val
    split = dataset.train_test_split(test_size=0.1)
    train_dataset = split["train"]
    eval_dataset = split["test"]

    dpo_config = DPOConfig(
        output_dir=str(config.output_dir),
        per_device_train_batch_size=config.batch_size,
        per_device_eval_batch_size=config.batch_size,
        gradient_accumulation_steps=config.gradient_accumulation_steps,
        learning_rate=config.learning_rate,
        num_train_epochs=config.epochs,
        beta=config.beta,
        logging_steps=10,
        eval_steps=50,
        save_steps=50,
        remove_unused_columns=False,
        report_to="mlflow",
    )

    trainer = DPOTrainer(
        model,
        ref_model=None, # trl creates it automatically for peft models
        args=dpo_config,
        beta=config.beta,
        train_dataset=train_dataset,
        eval_dataset=eval_dataset,
        tokenizer=tokenizer,
        peft_config=lora_config,
    )

    logger.info("Starting DPO training...")
    trainer.train()
    trainer.save_model(str(config.output_dir / "final"))
    logger.info(f"RLHF Model saved to {config.output_dir / 'final'}")


if __name__ == "__main__":
    config = RLHFConfig()
    train_dpo(config)
