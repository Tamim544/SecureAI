"""
SecureAI Configuration Loader.

Loads YAML config with environment variable overrides.
"""
from __future__ import annotations

import os
from functools import lru_cache
from pathlib import Path
from typing import Any

import yaml
from pydantic import BaseModel, Field
from pydantic_settings import BaseSettings


# ──────────────────────────────────────────────
# Config Models
# ──────────────────────────────────────────────

class PostgresConfig(BaseModel):
    host: str = "localhost"
    port: int = 5432
    name: str = "secureai"
    user: str = "secureai"
    password: str = "secureai_local"

    @property
    def dsn(self) -> str:
        return f"postgresql+asyncpg://{self.user}:{self.password}@{self.host}:{self.port}/{self.name}"


class Neo4jConfig(BaseModel):
    uri: str = "bolt://localhost:7687"
    user: str = "neo4j"
    password: str = "secureai_neo4j"


class RedisConfig(BaseModel):
    host: str = "localhost"
    port: int = 6379

    @property
    def url(self) -> str:
        return f"redis://{self.host}:{self.port}"


class DatabaseConfig(BaseModel):
    postgres: PostgresConfig = Field(default_factory=PostgresConfig)
    neo4j: Neo4jConfig = Field(default_factory=Neo4jConfig)
    redis: RedisConfig = Field(default_factory=RedisConfig)


class HNSWConfig(BaseModel):
    m: int = 16
    ef_construction: int = 200


class QdrantConfig(BaseModel):
    host: str = "localhost"
    port: int = 6333
    collections: dict[str, str] = Field(default_factory=lambda: {
        "code_functions": "code_functions",
        "vuln_patterns": "vuln_patterns",
        "fix_patterns": "fix_patterns",
        "cve_descriptions": "cve_descriptions",
    })


class VectorStoreConfig(BaseModel):
    qdrant: QdrantConfig = Field(default_factory=QdrantConfig)
    embedding_dim: int = 768
    hnsw: HNSWConfig = Field(default_factory=HNSWConfig)


class ModelConfig(BaseModel):
    base_model: str
    checkpoint_path: str
    batch_size: int = 16
    max_length: int = 512
    device: str = "mps"


class FixGeneratorConfig(ModelConfig):
    max_new_tokens: int = 512
    temperature: float = 0.2
    top_p: float = 0.95


class ModelsConfig(BaseModel):
    embedding: ModelConfig = Field(default_factory=lambda: ModelConfig(
        base_model="microsoft/graphcodebert-base",
        checkpoint_path="checkpoints/embedding_model",
        batch_size=32,
    ))
    classifier: ModelConfig = Field(default_factory=lambda: ModelConfig(
        base_model="microsoft/graphcodebert-base",
        checkpoint_path="checkpoints/classifier",
    ))
    fix_generator: FixGeneratorConfig = Field(default_factory=lambda: FixGeneratorConfig(
        base_model="bigcode/starcoderbase-1b",
        checkpoint_path="checkpoints/fix_generator",
    ))
    reward_model: ModelConfig = Field(default_factory=lambda: ModelConfig(
        base_model="microsoft/graphcodebert-base",
        checkpoint_path="checkpoints/reward_model",
    ))


class TaintConfig(BaseModel):
    max_depth: int = 20
    interprocedural: bool = True
    max_call_depth: int = 5


class AnalysisConfig(BaseModel):
    supported_languages: list[str] = Field(default_factory=lambda: ["python", "javascript"])
    taint: TaintConfig = Field(default_factory=TaintConfig)
    patterns_dir: str = "core/pattern_db/rules"
    chunk_size: int = 50
    chunk_overlap: int = 10


class AppConfig(BaseModel):
    name: str = "SecureAI"
    version: str = "0.1.0"
    debug: bool = False
    database: DatabaseConfig = Field(default_factory=DatabaseConfig)
    vector_store: VectorStoreConfig = Field(default_factory=VectorStoreConfig)
    models: ModelsConfig = Field(default_factory=ModelsConfig)
    analysis: AnalysisConfig = Field(default_factory=AnalysisConfig)


# ──────────────────────────────────────────────
# Loader
# ──────────────────────────────────────────────

def _deep_merge(base: dict, override: dict) -> dict:
    """Recursively merge override into base."""
    result = base.copy()
    for key, val in override.items():
        if key in result and isinstance(result[key], dict) and isinstance(val, dict):
            result[key] = _deep_merge(result[key], val)
        else:
            result[key] = val
    return result


def _load_yaml(path: Path) -> dict[str, Any]:
    if path.exists():
        with open(path) as f:
            return yaml.safe_load(f) or {}
    return {}


@lru_cache(maxsize=1)
def get_config(config_path: str | None = None) -> AppConfig:
    """
    Load configuration. Priority (highest to lowest):
      1. Environment variables (SECUREAI__KEY=value)
      2. config/config.local.yaml (git-ignored, for dev overrides)
      3. config/config.yaml (committed defaults)
    """
    root = Path(__file__).parent.parent
    base_cfg = _load_yaml(root / "config" / "config.yaml")
    local_cfg = _load_yaml(root / "config" / "config.local.yaml")
    merged = _deep_merge(base_cfg, local_cfg)
    return AppConfig.model_validate(merged)
