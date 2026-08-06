"""Fix service: wraps the FixGenerator ML model."""
from __future__ import annotations
from loguru import logger


class FixService:
    def __init__(self) -> None:
        self._generator = None
        logger.info("FixService initialized (model loads lazily on first request)")

    def _ensure_loaded(self) -> None:
        if self._generator is None:
            try:
                from ml.fix_generator.sft_trainer import FixGenerator, SFTConfig
                from pathlib import Path
                checkpoint = Path("checkpoints/fix_generator/final")
                if checkpoint.exists():
                    self._generator = FixGenerator.from_checkpoint(str(checkpoint))
                    logger.info("Fix generator model loaded")
                else:
                    logger.warning("Fix generator checkpoint not found. Train the model first.")
            except Exception as e:
                logger.error(f"Failed to load fix generator: {e}")

    async def generate(
        self,
        finding_id: str,
        vulnerable_code: str,
        language: str,
        cwe_id: str,
        severity: str,
        taint_path: str = "",
        num_candidates: int = 3,
    ) -> dict:
        self._ensure_loaded()

        if self._generator is None:
            # Fallback: return rule-based suggestion
            from core.taint_engine.analyzer import CWEType, TaintEngine
            engine = TaintEngine()
            try:
                cwe_enum = CWEType(cwe_id)
                suggestion = engine._suggest_fix(cwe_enum)
            except ValueError:
                suggestion = "Review the code and sanitize all user inputs before using them in sensitive operations."

            return {
                "candidates": [suggestion],
                "recommended": suggestion,
                "explanation": f"Rule-based suggestion for {cwe_id}. Train the fix generator model for AI-powered fixes.",
            }

        candidates = self._generator.generate_fix(
            language=language,
            cwe_id=cwe_id,
            severity=severity,
            vulnerable_code=vulnerable_code,
            taint_path=taint_path,
            num_candidates=num_candidates,
        )

        return {
            "candidates": candidates,
            "recommended": candidates[0] if candidates else "",
            "explanation": f"AI-generated fix for {cwe_id} ({severity}). Review before applying.",
        }
