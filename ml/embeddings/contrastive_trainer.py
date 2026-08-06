"""
Vulnerability-Aware Code Embedding Model.

Trains a contrastive embedding model on (vulnerable_code, fixed_code) pairs
so that:
  - vulnerable_code and fixed_code with the same CWE are CLOSE in embedding space
  - vulnerable_code and code with different CWE types are FAR apart
  - fixed/safe code clusters separately from vulnerable code

This creates a security-aware embedding space that enables:
  1. Semantic similarity search: "find code similar to this CVE pattern"
  2. Clustering: group vulnerabilities by type automatically
  3. Anomaly detection: flag code that's close to known vulnerable patterns

Architecture:
  GraphCodeBERT (125M params) → Mean Pooling → L2 Normalize → 768-dim embedding
  Trained with NT-Xent (normalized temperature-scaled cross entropy) contrastive loss

Free Training Strategy:
  - Kaggle Notebooks: 30 GPU hours/week (P100/T4) — free
  - Google Colab: T4 GPU, ~12h sessions — free
  - Mac M1 Pro: MPS backend — good for development/testing
"""
from __future__ import annotations

import math
import random
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import torch
import torch.nn as nn
import torch.nn.functional as F
from torch.utils.data import DataLoader, Dataset
from loguru import logger


# ──────────────────────────────────────────────
# Dataset
# ──────────────────────────────────────────────

@dataclass
class ContrastiveSample:
    """A training sample for contrastive learning."""
    anchor: str       # code snippet (vulnerable or safe)
    positive: str     # similar code (same vulnerability type)
    negative: str     # different code (different vulnerability or safe)
    anchor_label: str # CWE type label
    positive_label: str
    negative_label: str


class VulnerabilityPairDataset(Dataset):
    """
    Dataset of (vulnerable, fixed) code pairs for contrastive learning.

    Each item is a triplet: (anchor, positive, hard_negative)
    - anchor: a vulnerable code snippet
    - positive: the fix for that same vulnerability (should be nearby in embedding space)
    - hard_negative: a snippet with a different vulnerability type (should be far away)
    """

    def __init__(
        self,
        data_path: Path,
        tokenizer: Any,
        max_length: int = 512,
        augment: bool = True,
    ) -> None:
        self.tokenizer = tokenizer
        self.max_length = max_length
        self.augment = augment
        self.samples: list[dict] = self._load(data_path)
        logger.info(f"Loaded {len(self.samples)} vulnerability pairs from {data_path}")

    def _load(self, path: Path) -> list[dict]:
        """Load processed vulnerability pair JSONL file."""
        import json
        samples = []
        if not path.exists():
            logger.warning(f"Data file not found: {path}. Using empty dataset.")
            return []
        with open(path) as f:
            for line in f:
                try:
                    samples.append(json.loads(line.strip()))
                except json.JSONDecodeError:
                    continue
        return samples

    def _augment(self, code: str) -> str:
        """
        Code augmentation for better generalization.
        Applies one random augmentation.
        """
        aug_fn = random.choice([
            self._rename_variables,
            self._add_comment,
            self._remove_comments,
            lambda x: x,  # identity (no augmentation)
        ])
        return aug_fn(code)

    def _rename_variables(self, code: str) -> str:
        """Rename a random variable (for invariance to variable naming)."""
        import re
        identifiers = re.findall(r'\b([a-z_][a-z0-9_]{2,})\b', code)
        if not identifiers:
            return code
        target = random.choice(identifiers)
        replacement = f"var_{random.randint(1, 99)}"
        return code.replace(target, replacement, 1)

    def _add_comment(self, code: str) -> str:
        """Insert a random innocuous comment."""
        lines = code.splitlines()
        if not lines:
            return code
        idx = random.randint(0, len(lines) - 1)
        indent = len(lines[idx]) - len(lines[idx].lstrip())
        comment = " " * indent + f"# step {random.randint(1, 10)}"
        lines.insert(idx, comment)
        return "\n".join(lines)

    def _remove_comments(self, code: str) -> str:
        """Strip single-line comments."""
        import re
        return re.sub(r'#[^\n]*', '', code)

    def _tokenize(self, code: str) -> dict[str, torch.Tensor]:
        """Tokenize code with the model's tokenizer."""
        return self.tokenizer(
            code,
            max_length=self.max_length,
            padding="max_length",
            truncation=True,
            return_tensors="pt",
        )

    def __len__(self) -> int:
        return len(self.samples)

    def __getitem__(self, idx: int) -> dict[str, Any]:
        sample = self.samples[idx]
        anchor_code = sample["vulnerable_code"]
        positive_code = sample["fixed_code"]

        # Hard negative: pick a sample with a different CWE
        neg_idx = idx
        anchor_cwe = sample.get("cwe_id", "UNKNOWN")
        attempts = 0
        while attempts < 10:
            neg_idx = random.randint(0, len(self.samples) - 1)
            if self.samples[neg_idx].get("cwe_id", "UNKNOWN") != anchor_cwe:
                break
            attempts += 1
        negative_code = self.samples[neg_idx]["vulnerable_code"]

        if self.augment:
            anchor_code = self._augment(anchor_code)
            positive_code = self._augment(positive_code)
            negative_code = self._augment(negative_code)

        anchor_enc = self._tokenize(anchor_code)
        positive_enc = self._tokenize(positive_code)
        negative_enc = self._tokenize(negative_code)

        return {
            "anchor_input_ids": anchor_enc["input_ids"].squeeze(0),
            "anchor_attention_mask": anchor_enc["attention_mask"].squeeze(0),
            "positive_input_ids": positive_enc["input_ids"].squeeze(0),
            "positive_attention_mask": positive_enc["attention_mask"].squeeze(0),
            "negative_input_ids": negative_enc["input_ids"].squeeze(0),
            "negative_attention_mask": negative_enc["attention_mask"].squeeze(0),
            "cwe_label": anchor_cwe,
        }


# ──────────────────────────────────────────────
# Model Architecture
# ──────────────────────────────────────────────

class CodeEmbeddingModel(nn.Module):
    """
    Security-aware code embedding model.

    Uses GraphCodeBERT as the encoder backbone with mean pooling
    and L2 normalization to produce 768-dim unit-norm embeddings.

    The embedding space is trained to cluster:
    - Vulnerable code close to other code with the same CWE
    - Fixed/patched code close to (but distinguishable from) its vulnerable counterpart
    - Different vulnerability types far apart
    """

    def __init__(self, base_model_name: str = "microsoft/graphcodebert-base") -> None:
        super().__init__()
        from transformers import AutoModel
        self.encoder = AutoModel.from_pretrained(base_model_name)
        self.embedding_dim = self.encoder.config.hidden_size  # 768

    def mean_pooling(
        self,
        token_embeddings: torch.Tensor,
        attention_mask: torch.Tensor,
    ) -> torch.Tensor:
        """Mean pool over non-padding tokens."""
        mask = attention_mask.unsqueeze(-1).expand(token_embeddings.size()).float()
        return torch.sum(token_embeddings * mask, dim=1) / torch.clamp(mask.sum(dim=1), min=1e-9)

    def forward(
        self,
        input_ids: torch.Tensor,
        attention_mask: torch.Tensor,
    ) -> torch.Tensor:
        """
        Encode code tokens to a normalized embedding vector.

        Returns:
            embeddings: shape (batch_size, 768), L2-normalized
        """
        outputs = self.encoder(input_ids=input_ids, attention_mask=attention_mask)
        pooled = self.mean_pooling(outputs.last_hidden_state, attention_mask)
        return F.normalize(pooled, p=2, dim=1)

    def encode(self, code_snippets: list[str], tokenizer: Any, device: str = "cpu") -> torch.Tensor:
        """
        Convenience method: encode a list of code strings to embeddings.

        Args:
            code_snippets: list of code strings
            tokenizer: HuggingFace tokenizer
            device: computation device

        Returns:
            embeddings: shape (N, 768)
        """
        self.eval()
        encoded = tokenizer(
            code_snippets,
            max_length=512,
            padding=True,
            truncation=True,
            return_tensors="pt",
        )
        with torch.no_grad():
            return self.forward(
                encoded["input_ids"].to(device),
                encoded["attention_mask"].to(device),
            )


# ──────────────────────────────────────────────
# Contrastive Loss
# ──────────────────────────────────────────────

class NTXentLoss(nn.Module):
    """
    Normalized Temperature-scaled Cross Entropy Loss (NT-Xent).

    Used in SimCLR / contrastive learning. For each anchor,
    the positive is the correct match and all other samples
    in the batch are treated as negatives.

    Temperature τ controls the sharpness of the distribution:
    - Lower τ → harder, more discriminative comparisons
    - Higher τ → softer, more forgiving comparisons
    """

    def __init__(self, temperature: float = 0.07) -> None:
        super().__init__()
        self.temperature = temperature

    def forward(
        self,
        anchors: torch.Tensor,
        positives: torch.Tensor,
        negatives: torch.Tensor,
    ) -> torch.Tensor:
        """
        Compute triplet NT-Xent loss.

        Args:
            anchors: (B, D) anchor embeddings
            positives: (B, D) positive embeddings
            negatives: (B, D) negative embeddings

        Returns:
            Scalar loss
        """
        B = anchors.size(0)

        # Concatenate positives and negatives to form the comparison pool
        all_embeds = torch.cat([positives, negatives], dim=0)  # (2B, D)

        # Similarity between each anchor and all positives+negatives
        sim = torch.mm(anchors, all_embeds.T) / self.temperature  # (B, 2B)

        # Labels: positive is at position i (first B rows are positives)
        labels = torch.arange(B, device=anchors.device)

        loss = F.cross_entropy(sim, labels)
        return loss


# ──────────────────────────────────────────────
# Trainer
# ──────────────────────────────────────────────

class EmbeddingTrainer:
    """
    Training loop for the contrastive code embedding model.

    Designed to run on:
    - Mac M1 Pro (MPS backend) for development
    - Kaggle T4/P100 (CUDA) for production training
    - Google Colab T4 (CUDA) for free training
    """

    def __init__(
        self,
        model: CodeEmbeddingModel,
        train_dataloader: DataLoader,
        val_dataloader: DataLoader,
        learning_rate: float = 2e-5,
        temperature: float = 0.07,
        checkpoint_dir: Path = Path("checkpoints/embedding_model"),
        device: str = "auto",
    ) -> None:
        self.device = self._select_device(device)
        self.model = model.to(self.device)
        self.train_loader = train_dataloader
        self.val_loader = val_dataloader
        self.criterion = NTXentLoss(temperature=temperature)
        self.optimizer = torch.optim.AdamW(
            self.model.parameters(),
            lr=learning_rate,
            weight_decay=0.01,
        )
        self.checkpoint_dir = checkpoint_dir
        self.checkpoint_dir.mkdir(parents=True, exist_ok=True)
        self.best_val_loss = float("inf")

        logger.info(f"EmbeddingTrainer initialized on device: {self.device}")

    def _select_device(self, device: str) -> str:
        if device == "auto":
            if torch.cuda.is_available():
                return "cuda"
            elif hasattr(torch.backends, "mps") and torch.backends.mps.is_available():
                return "mps"
            return "cpu"
        return device

    def train_epoch(self) -> float:
        self.model.train()
        total_loss = 0.0

        for batch_idx, batch in enumerate(self.train_loader):
            anchor_ids = batch["anchor_input_ids"].to(self.device)
            anchor_mask = batch["anchor_attention_mask"].to(self.device)
            pos_ids = batch["positive_input_ids"].to(self.device)
            pos_mask = batch["positive_attention_mask"].to(self.device)
            neg_ids = batch["negative_input_ids"].to(self.device)
            neg_mask = batch["negative_attention_mask"].to(self.device)

            self.optimizer.zero_grad()

            anchor_emb = self.model(anchor_ids, anchor_mask)
            pos_emb = self.model(pos_ids, pos_mask)
            neg_emb = self.model(neg_ids, neg_mask)

            loss = self.criterion(anchor_emb, pos_emb, neg_emb)
            loss.backward()

            nn.utils.clip_grad_norm_(self.model.parameters(), max_norm=1.0)
            self.optimizer.step()

            total_loss += loss.item()

            if batch_idx % 50 == 0:
                logger.info(f"  Step {batch_idx}/{len(self.train_loader)} | Loss: {loss.item():.4f}")

        return total_loss / len(self.train_loader)

    @torch.no_grad()
    def validate(self) -> float:
        self.model.eval()
        total_loss = 0.0

        for batch in self.val_loader:
            anchor_emb = self.model(
                batch["anchor_input_ids"].to(self.device),
                batch["anchor_attention_mask"].to(self.device),
            )
            pos_emb = self.model(
                batch["positive_input_ids"].to(self.device),
                batch["positive_attention_mask"].to(self.device),
            )
            neg_emb = self.model(
                batch["negative_input_ids"].to(self.device),
                batch["negative_attention_mask"].to(self.device),
            )
            loss = self.criterion(anchor_emb, pos_emb, neg_emb)
            total_loss += loss.item()

        return total_loss / len(self.val_loader)

    def train(self, epochs: int = 20) -> None:
        """Full training loop."""
        logger.info(f"Starting contrastive training for {epochs} epochs")

        scheduler = torch.optim.lr_scheduler.CosineAnnealingLR(
            self.optimizer, T_max=epochs, eta_min=1e-7
        )

        for epoch in range(1, epochs + 1):
            logger.info(f"\n{'='*50}")
            logger.info(f"Epoch {epoch}/{epochs}")

            train_loss = self.train_epoch()
            val_loss = self.validate()
            scheduler.step()

            logger.info(f"Train Loss: {train_loss:.4f} | Val Loss: {val_loss:.4f}")

            # Save best model
            if val_loss < self.best_val_loss:
                self.best_val_loss = val_loss
                self._save_checkpoint(epoch, val_loss, is_best=True)
                logger.info(f"✓ New best model saved (val_loss={val_loss:.4f})")

            # Save periodic checkpoint
            if epoch % 5 == 0:
                self._save_checkpoint(epoch, val_loss, is_best=False)

        logger.info(f"\nTraining complete. Best val loss: {self.best_val_loss:.4f}")

    def _save_checkpoint(self, epoch: int, val_loss: float, is_best: bool) -> None:
        checkpoint = {
            "epoch": epoch,
            "model_state_dict": self.model.state_dict(),
            "optimizer_state_dict": self.optimizer.state_dict(),
            "val_loss": val_loss,
        }
        suffix = "best" if is_best else f"epoch_{epoch:03d}"
        path = self.checkpoint_dir / f"embedding_{suffix}.pt"
        torch.save(checkpoint, path)


# ──────────────────────────────────────────────
# Entry Point
# ──────────────────────────────────────────────

def train_embedding_model(
    data_path: Path,
    base_model: str = "microsoft/graphcodebert-base",
    batch_size: int = 16,      # 16 for M1 Pro 16GB, 64 for Kaggle T4
    epochs: int = 20,
    lr: float = 2e-5,
    temperature: float = 0.07,
    checkpoint_dir: Path = Path("checkpoints/embedding_model"),
    device: str = "auto",
) -> None:
    """
    Train the contrastive code embedding model.

    For FREE GPU training, use:
    - Kaggle: https://www.kaggle.com → New Notebook → GPU T4 x2
    - Colab:  https://colab.research.google.com → Runtime → T4 GPU

    Set batch_size=64 when using T4 (16GB VRAM).
    """
    from transformers import AutoTokenizer

    logger.info(f"Loading tokenizer: {base_model}")
    tokenizer = AutoTokenizer.from_pretrained(base_model)

    # Split into train/val
    train_ds = VulnerabilityPairDataset(data_path / "train.jsonl", tokenizer, augment=True)
    val_ds = VulnerabilityPairDataset(data_path / "val.jsonl", tokenizer, augment=False)

    train_loader = DataLoader(train_ds, batch_size=batch_size, shuffle=True, num_workers=2)
    val_loader = DataLoader(val_ds, batch_size=batch_size, shuffle=False, num_workers=2)

    logger.info(f"Loading base model: {base_model}")
    model = CodeEmbeddingModel(base_model)

    trainer = EmbeddingTrainer(
        model=model,
        train_dataloader=train_loader,
        val_dataloader=val_loader,
        learning_rate=lr,
        temperature=temperature,
        checkpoint_dir=checkpoint_dir,
        device=device,
    )

    trainer.train(epochs=epochs)


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="Train SecureAI embedding model")
    parser.add_argument("--data-path", type=Path, default=Path("data/processed/vuln_pairs"))
    parser.add_argument("--base-model", default="microsoft/graphcodebert-base")
    parser.add_argument("--batch-size", type=int, default=16)
    parser.add_argument("--epochs", type=int, default=20)
    parser.add_argument("--lr", type=float, default=2e-5)
    parser.add_argument("--temperature", type=float, default=0.07)
    parser.add_argument("--checkpoint-dir", type=Path, default=Path("checkpoints/embedding_model"))
    parser.add_argument("--device", default="auto")
    args = parser.parse_args()

    train_embedding_model(
        data_path=args.data_path,
        base_model=args.base_model,
        batch_size=args.batch_size,
        epochs=args.epochs,
        lr=args.lr,
        temperature=args.temperature,
        checkpoint_dir=args.checkpoint_dir,
        device=args.device,
    )
