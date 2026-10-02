"""Centralized Configuration and Version Provenance for ScamShield AI.

Strictly separates:
1. FROZEN MODEL CONFIGURATION (Immutable: exact frozen thresholds, paths, model dimensions).
2. VERSION & PROVENANCE METADATA (Project, schema, dataset, preprocessing, and model versions).
3. RUNTIME / APPLICATION CONFIGURATION (Resource bounds, caching, logging, feature flags).

INVARIANT:
- Frozen thresholds (Phase 3 = 0.30, Phase 13 Model B = 0.55, Model C = 0.50, Model D = 0.50)
  are strictly read-only and cannot be altered via environment or runtime overrides.
- 100% offline security: OFFLINE_MODE defaults to True with 0 outbound network calls.
"""

from dataclasses import dataclass, field
import os
from pathlib import Path
from typing import Any, Dict, Mapping, Optional, Tuple
from types import MappingProxyType

# Project root path resolution
PROJECT_ROOT = Path(__file__).resolve().parents[2]


# =====================================================================
# 1. IMMUTABLE FROZEN MODEL SPECIFICATIONS (PHASES 1–13)
# =====================================================================

@dataclass(frozen=True)
class FrozenModelConfig:
    """Immutable configuration holding authoritative model parameters and thresholds."""

    # Authoritative Frozen Decision Thresholds
    PHASE3_BASELINE_THRESHOLD: float = 0.30
    PHASE13_MODEL_B_THRESHOLD: float = 0.55
    PHASE13_MODEL_C_THRESHOLD: float = 0.50
    PHASE13_MODEL_D_THRESHOLD: float = 0.50

    # Model and Vectorizer Artifact Paths
    BASELINE_MODEL_DIR: Path = PROJECT_ROOT / "models" / "baseline"
    PHASE13_CHAR_NGRAM_DIR: Path = PROJECT_ROOT / "models" / "phase13" / "char_ngram"
    PHASE13_HYBRID_DIR: Path = PROJECT_ROOT / "models" / "phase13" / "hybrid_fusion"
    PHASE13_SEMANTIC_DIR: Path = PROJECT_ROOT / "models" / "phase13" / "semantic_dense"

    # Reference Corpus and Knowledge Base Paths
    SEMANTIC_REFERENCE_DIR: Path = PROJECT_ROOT / "data" / "semantic" / "reference"
    KNOWLEDGE_BASE_DIR: Path = PROJECT_ROOT / "data" / "knowledge_base"

    # Neural Embedding Specifications
    EMBEDDING_MODEL_NAME: str = "sentence-transformers/all-MiniLM-L6-v2"
    EMBEDDING_DIMENSION: int = 384

    # Character N-gram Hyperparameters (Frozen in Phase 13)
    CHAR_NGRAM_RANGE: Tuple[int, int] = (3, 5)
    CHAR_MAX_FEATURES: int = 15000

    # Declarative Tactics Count (Frozen in Phase 6)
    DECLARATIVE_TACTIC_COUNT: int = 23


# Global immutable instance of frozen configuration
FROZEN_CONFIG = FrozenModelConfig()


# =====================================================================
# 2. VERSION & PROVENANCE METADATA
# =====================================================================

@dataclass(frozen=True)
class VersionMetadata:
    """Project-wide versioning and provenance tracking."""

    PROJECT_VERSION: str = "1.0.0"
    PHASE_VERSION: str = "Phase 14 (Production Engineering & Optimization)"
    SCHEMA_VERSION: str = "1.0.0"
    DATASET_VERSION: str = "v1.0-uci-curated"
    PREPROCESSING_VERSION: str = "v1.0-phase2"
    CONFIG_VERSION: str = "1.0.0"

    MODEL_VERSIONS: Mapping[str, str] = MappingProxyType({
        "baseline_tfidf_lr": "v1.0-phase3",
        "char_ngram_model_b": "v1.0-phase13",
        "hybrid_fusion_model_c": "v1.0-phase13",
        "semantic_dense_model_d": "v1.0-phase13",
        "sentence_transformer_minilm": "all-MiniLM-L6-v2",
        "tactic_engine": "v1.0-phase6-23rules",
    })

    def to_dict(self) -> Dict[str, Any]:
        """Serializes version metadata for inclusion in investigation reports."""
        return {
            "project_version": self.PROJECT_VERSION,
            "phase_version": self.PHASE_VERSION,
            "schema_version": self.SCHEMA_VERSION,
            "dataset_version": self.DATASET_VERSION,
            "preprocessing_version": self.PREPROCESSING_VERSION,
            "config_version": self.CONFIG_VERSION,
            "model_versions": dict(self.MODEL_VERSIONS),
        }


VERSION_METADATA = VersionMetadata()


# =====================================================================
# 3. RUNTIME & APPLICATION CONFIGURATION
# =====================================================================

@dataclass
class RuntimeConfig:
    """Configurable runtime settings, resource guards, and operational flags."""

    # Resource Bounds (Defensive Guards)
    # Rationale: 50,000 characters accommodates long communications (~10,000 words) while capping regex CPU time
    MAX_TEXT_LENGTH: int = 50_000

    # Rationale: Standard RFC 2616 / modern browser maximum URL length boundary
    MAX_URL_LENGTH: int = 2_048

    # Rationale: Prevents denial-of-service via massive link dumps in a single submission
    MAX_URL_COUNT: int = 50

    # Rationale: 10 MB accommodates high-resolution mobile screenshots while preventing OOM
    MAX_IMAGE_BYTES: int = 10 * 1024 * 1024

    # Rationale: 4096px prevents PIL decompression bombs and excessive raster memory consumption
    MAX_IMAGE_DIMENSION: int = 4096

    # Allowed screenshot / document image file extensions
    ALLOWED_IMAGE_EXTENSIONS: Tuple[str, ...] = (".png", ".jpg", ".jpeg", ".webp")

    # Operational Security
    # 100% offline execution invariant
    OFFLINE_MODE: bool = True

    # Process Caching
    ENABLE_PROCESS_MODEL_CACHE: bool = True
    ENABLE_EMBEDDER_CACHE: bool = True
    ENABLE_RAG_INDEX_CACHE: bool = True

    # Logging & Observability
    LOG_LEVEL: str = "INFO"
    SANITIZE_LOGS: bool = True
    LOG_RETENTION_DAYS: int = 30

    # Feature Flags
    ENABLE_SEMANTIC_ANALYSIS: bool = True
    ENABLE_OCR: bool = True
    ENABLE_VISUAL_ANALYSIS: bool = True

    # RAG Explanation Defaults
    DEFAULT_EXPLANATION_PROVIDER: str = "mock"
    DEFAULT_RAG_TOP_K: int = 3

    @classmethod
    def from_env(cls) -> "RuntimeConfig":
        """Constructs runtime config with optional environment overrides."""
        cfg = cls()

        # Parse log level
        env_log = os.environ.get("SCAMSHIELD_LOG_LEVEL")
        if env_log:
            cfg.LOG_LEVEL = env_log.upper()

        # Parse provider
        env_prov = os.environ.get("SCAMSHIELD_EXPLANATION_PROVIDER")
        if env_prov:
            cfg.DEFAULT_EXPLANATION_PROVIDER = env_prov.lower().strip()

        # Parse feature flags
        if os.environ.get("SCAMSHIELD_DISABLE_SEMANTIC") == "1":
            cfg.ENABLE_SEMANTIC_ANALYSIS = False
        if os.environ.get("SCAMSHIELD_DISABLE_CACHE") == "1":
            cfg.ENABLE_PROCESS_MODEL_CACHE = False
            cfg.ENABLE_EMBEDDER_CACHE = False
            cfg.ENABLE_RAG_INDEX_CACHE = False

        return cfg


# Active runtime configuration instance
_ACTIVE_RUNTIME_CONFIG: Optional[RuntimeConfig] = None


def get_runtime_config() -> RuntimeConfig:
    """Returns the active runtime configuration singleton."""
    global _ACTIVE_RUNTIME_CONFIG
    if _ACTIVE_RUNTIME_CONFIG is None:
        _ACTIVE_RUNTIME_CONFIG = RuntimeConfig.from_env()
    return _ACTIVE_RUNTIME_CONFIG


def get_frozen_config() -> FrozenModelConfig:
    """Returns the immutable frozen model configuration."""
    return FROZEN_CONFIG


def get_version_metadata() -> VersionMetadata:
    """Returns the project version and provenance metadata."""
    return VERSION_METADATA
