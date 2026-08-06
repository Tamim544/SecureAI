"""
Evaluation Scripts for Vulnerability Classification and Fix Generation.

Computes metrics:
- Classification: F1, Precision, Recall, False Positive Rate (FPR)
- Fix Generation: Exact Match (EM), Syntax Pass Rate, BLEU
"""
from __future__ import annotations

from typing import List, Dict, Any
from loguru import logger
import json

try:
    from sklearn.metrics import f1_score, precision_score, recall_score, confusion_matrix
except ImportError:
    f1_score = precision_score = recall_score = confusion_matrix = None


class ModelEvaluator:
    def __init__(self):
        pass

    def evaluate_classifier(self, y_true: List[int], y_pred: List[int]) -> Dict[str, float]:
        """Evaluate the vulnerability classification model."""
        if f1_score is None:
            logger.error("scikit-learn not installed. Cannot compute metrics.")
            return {}

        metrics = {
            "f1": float(f1_score(y_true, y_pred, average="macro")),
            "precision": float(precision_score(y_true, y_pred, average="macro", zero_division=0)),
            "recall": float(recall_score(y_true, y_pred, average="macro", zero_division=0)),
        }
        
        # Calculate FPR if binary classification (0=safe, 1=vuln)
        if set(y_true).issubset({0, 1}):
            try:
                tn, fp, fn, tp = confusion_matrix(y_true, y_pred).ravel()
                metrics["fpr"] = float(fp / (fp + tn)) if (fp + tn) > 0 else 0.0
            except ValueError:
                pass

        logger.info(f"Classifier Evaluation: {json.dumps(metrics)}")
        return metrics

    def evaluate_fixes(self, generated_fixes: List[str], target_fixes: List[str]) -> Dict[str, float]:
        """Evaluate the fix generator model."""
        exact_matches = 0
        total = len(generated_fixes)
        
        if total == 0:
            return {"exact_match": 0.0, "syntax_pass_rate": 0.0}

        # Basic Exact Match
        for gen, target in zip(generated_fixes, target_fixes):
            if gen.strip() == target.strip():
                exact_matches += 1

        # Syntactic Pass Rate (Try parsing the python AST)
        syntax_passed = 0
        import ast
        for gen in generated_fixes:
            try:
                ast.parse(gen)
                syntax_passed += 1
            except SyntaxError:
                pass

        metrics = {
            "exact_match": float(exact_matches / total),
            "syntax_pass_rate": float(syntax_passed / total)
        }
        
        logger.info(f"Fix Generator Evaluation: {json.dumps(metrics)}")
        return metrics
