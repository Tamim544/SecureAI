"""
MLflow Experiment Tracking.

Centralized logging for model training, metrics, hyperparameters,
and model versioning.
"""
from __future__ import annotations

import os
from typing import Any, Dict
from loguru import logger

try:
    import mlflow
except ImportError:
    mlflow = None


class ExperimentTracker:
    def __init__(self, experiment_name: str, tracking_uri: str = "sqlite:///mlruns.db"):
        self.experiment_name = experiment_name
        self.tracking_uri = tracking_uri
        self.active_run = None
        
        if mlflow:
            try:
                mlflow.set_tracking_uri(self.tracking_uri)
                mlflow.set_experiment(self.experiment_name)
                logger.info(f"Initialized MLflow experiment: {self.experiment_name}")
            except Exception as e:
                logger.warning(f"Failed to initialize MLflow: {e}")

    def start_run(self, run_name: str = None) -> None:
        if not mlflow:
            return
        self.active_run = mlflow.start_run(run_name=run_name)
        logger.info(f"Started MLflow run: {run_name}")

    def log_params(self, params: Dict[str, Any]) -> None:
        if not mlflow or not self.active_run:
            return
        mlflow.log_params(params)

    def log_metrics(self, metrics: Dict[str, float], step: int = None) -> None:
        if not mlflow or not self.active_run:
            return
        mlflow.log_metrics(metrics, step=step)

    def log_model(self, model: Any, artifact_path: str = "model") -> None:
        if not mlflow or not self.active_run:
            return
        try:
            # Assuming PyTorch model for this project
            mlflow.pytorch.log_model(model, artifact_path)
            logger.info(f"Model logged to MLflow under {artifact_path}")
        except Exception as e:
            logger.error(f"Failed to log model to MLflow: {e}")

    def end_run(self) -> None:
        if not mlflow or not self.active_run:
            return
        mlflow.end_run()
        self.active_run = None
        logger.info("Ended MLflow run")

    def __enter__(self):
        self.start_run()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.end_run()
