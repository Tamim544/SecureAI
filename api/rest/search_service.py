"""Semantic search service."""
from __future__ import annotations
from loguru import logger


class SearchService:
    def __init__(self) -> None:
        self._encoder = None
        self._qdrant = None
        logger.info("SearchService initialized (lazy loading)")

    async def search(
        self,
        query: str,
        repo_path: str,
        top_k: int = 10,
        language: str | None = None,
    ) -> list[dict]:
        """Semantic search over indexed codebase."""
        # TODO: Full implementation in Phase 4 (vector store)
        # For now return placeholder
        return [
            {
                "file_path": f"{repo_path}/example.py",
                "function_name": "example_function",
                "line_start": 1,
                "line_end": 10,
                "relevance_score": 0.95,
                "code_preview": f"# Searching for: {query}",
                "vulnerability_match": None,
            }
        ]
