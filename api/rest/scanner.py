"""
Scanner Service: Orchestrates AST parsing + taint analysis + ML classification.
"""
from __future__ import annotations

import asyncio
import time
import uuid
from pathlib import Path
from typing import Any

from loguru import logger

from core.ast_engine.parser import ASTEngine
from core.taint_engine.analyzer import TaintEngine, VulnerabilityFinding


_job_store: dict[str, dict] = {}  # In-memory for now; use Redis in production


class ScannerService:
    """
    Orchestrates the full vulnerability scanning pipeline:
    1. Parse source code with ASTEngine
    2. Run taint analysis with TaintEngine
    3. (Optional) Run ML classifier for confidence scoring
    4. Return ranked findings
    """

    def __init__(self) -> None:
        self.ast_engine = ASTEngine()
        self.taint_engine = TaintEngine()
        self._ml_classifier: Any = None  # Lazy-loaded
        logger.info("ScannerService initialized")

    async def scan_snippet(
        self,
        code: str,
        language: str,
        filename: str = "<snippet>",
    ) -> list[VulnerabilityFinding]:
        """Scan a single code snippet."""
        from core.ast_engine.parser import Language
        lang_enum = Language(language)

        # Parse
        parse_result = self.ast_engine.parse_source(code, lang_enum, filename)

        # Taint analysis
        findings = self.taint_engine.analyze_file(parse_result)

        # Sort by severity
        severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
        findings.sort(key=lambda f: severity_order.get(f.severity.value, 5))

        logger.info(f"Snippet scan: {len(findings)} findings in {filename}")
        return findings

    async def scan_repo_async(
        self,
        job_id: str,
        repo_path: Path,
        languages: list[str],
        severity_threshold: str,
        max_files: int,
    ) -> None:
        """Async repo scan — runs in background."""
        _job_store[job_id] = {"status": "running", "findings": [], "progress": 0}
        start_time = time.time()

        try:
            all_findings: list[VulnerabilityFinding] = []
            extensions = {
                "python": [".py"],
                "javascript": [".js", ".mjs", ".jsx", ".ts", ".tsx"],
            }
            target_exts = set()
            for lang in languages:
                target_exts.update(extensions.get(lang, []))

            files = [
                f for f in repo_path.rglob("*")
                if f.suffix in target_exts
                and not any(part.startswith(".") for part in f.parts)
                and "node_modules" not in f.parts
                and "__pycache__" not in f.parts
            ][:max_files]

            logger.info(f"Job {job_id}: scanning {len(files)} files")

            for i, file_path in enumerate(files):
                try:
                    parse_result = self.ast_engine.parse_file(file_path)
                    findings = self.taint_engine.analyze_file(parse_result)
                    all_findings.extend(findings)
                except Exception as e:
                    logger.debug(f"Error scanning {file_path}: {e}")

                _job_store[job_id]["progress"] = int((i + 1) / len(files) * 100)

            # Filter by severity threshold
            severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
            threshold_level = severity_order.get(severity_threshold, 3)
            all_findings = [
                f for f in all_findings
                if severity_order.get(f.severity.value, 5) <= threshold_level
            ]

            duration_ms = (time.time() - start_time) * 1000
            _job_store[job_id] = {
                "status": "completed",
                "findings": all_findings,
                "duration_ms": duration_ms,
                "files_scanned": len(files),
                "progress": 100,
            }
            logger.info(f"Job {job_id}: completed — {len(all_findings)} findings in {duration_ms:.0f}ms")

        except Exception as e:
            _job_store[job_id] = {"status": "failed", "error": str(e), "progress": 0}
            logger.error(f"Job {job_id} failed: {e}")

    async def get_job_result(self, job_id: str) -> dict | None:
        return _job_store.get(job_id)

    async def get_stats(self) -> dict:
        return {
            "total_jobs": len(_job_store),
            "completed_jobs": sum(1 for j in _job_store.values() if j.get("status") == "completed"),
            "supported_languages": ["python", "javascript"],
            "models_loaded": ["ast_engine", "taint_engine"],
        }
