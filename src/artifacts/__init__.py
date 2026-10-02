"""Artifact management, validation, and process-level caching for ScamShield AI."""

from .cache import (
    ModelArtifactCache,
    clear_model_cache,
    get_cache_stats,
    get_cached_baseline_classifier,
    get_cached_char_classifier,
    get_cached_embedder,
    get_cached_knowledge_retriever,
    get_cached_semantic_reference_index,
)
from .manager import (
    ArtifactCorruptedError,
    ArtifactError,
    ArtifactIncompatibleError,
    ArtifactManager,
    ArtifactNotFoundError,
    FROZEN_ARTIFACT_CHECKSUMS,
    compute_file_sha256,
    validate_file_artifact,
)

__all__ = [
    "ArtifactError",
    "ArtifactNotFoundError",
    "ArtifactCorruptedError",
    "ArtifactIncompatibleError",
    "ArtifactManager",
    "FROZEN_ARTIFACT_CHECKSUMS",
    "compute_file_sha256",
    "validate_file_artifact",
    "ModelArtifactCache",
    "clear_model_cache",
    "get_cache_stats",
    "get_cached_baseline_classifier",
    "get_cached_char_classifier",
    "get_cached_embedder",
    "get_cached_knowledge_retriever",
    "get_cached_semantic_reference_index",
]
