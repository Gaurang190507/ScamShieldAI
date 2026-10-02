"""Process-level thread-safe singleton cache for heavy models and indexes.

Caches:
1. SentenceTransformer / TextEmbedder (PyTorch weights & tokenizer)
2. SemanticReferenceIndex (3,881 reference embeddings & metadata)
3. KnowledgeRetriever (Parsed regulatory chunks & fitted TF-IDF index)
4. BaselineTextClassifier (Phase 3 TF-IDF vectorizer & Logistic Regression)
5. CharNgramClassifier (Phase 13 Model B vectorizer & Logistic Regression)

SECURITY & INTEGRITY INVARIANTS:
- Does NOT cache individual user submissions, case IDs, or investigation results.
- Provides explicit cache invalidation mechanisms (clear_model_cache).
- Thread-safe access via re-entrant locking (threading.RLock).
- Deterministic lazy-loading: models are loaded on first access and reused.
"""

from pathlib import Path
import threading
from typing import Any, Dict, Optional, Union

from src.config.runtime_config import FROZEN_CONFIG, get_runtime_config
from .manager import ArtifactManager


class ModelArtifactCache:
    """Thread-safe singleton managing process-level model instances."""

    _instance = None
    _lock = threading.RLock()

    def __new__(cls):
        with cls._lock:
            if cls._instance is None:
                cls._instance = super(ModelArtifactCache, cls).__new__(cls)
                cls._instance._registry: Dict[str, Any] = {}
                cls._instance._stats = {"hits": 0, "misses": 0, "invalidations": 0}
            return cls._instance

    def get(self, key: str) -> Optional[Any]:
        """Retrieves an object from cache if caching is enabled."""
        config = get_runtime_config()
        if not config.ENABLE_PROCESS_MODEL_CACHE:
            return None

        with self._lock:
            if key in self._registry:
                self._stats["hits"] += 1
                return self._registry[key]
            self._stats["misses"] += 1
            return None

    def set(self, key: str, value: Any) -> None:
        """Stores an object in cache if caching is enabled."""
        config = get_runtime_config()
        if not config.ENABLE_PROCESS_MODEL_CACHE:
            return

        with self._lock:
            self._registry[key] = value

    def invalidate(self, key: str) -> bool:
        """Invalidates a single cached artifact."""
        with self._lock:
            if key in self._registry:
                del self._registry[key]
                self._stats["invalidations"] += 1
                return True
            return False

    def clear(self) -> None:
        """Flushes all cached models and resets stats."""
        with self._lock:
            self._registry.clear()
            self._stats["invalidations"] += 1

    def get_stats(self) -> Dict[str, Any]:
        """Returns cache telemetry and statistics."""
        with self._lock:
            return {
                "hits": self._stats["hits"],
                "misses": self._stats["misses"],
                "invalidations": self._stats["invalidations"],
                "cached_keys": list(self._registry.keys()),
                "total_cached_objects": len(self._registry),
            }


# Singleton cache accessor
_CACHE = ModelArtifactCache()


def get_cached_embedder(
    model_name: Optional[str] = None,
    device: Optional[str] = None,
):
    """Retrieves or loads the singleton TextEmbedder instance."""
    from src.semantic.embedder import TextEmbedder

    m_name = model_name or FROZEN_CONFIG.EMBEDDING_MODEL_NAME
    dev = device or "cpu"
    cache_key = f"embedder:{m_name}:{dev}"

    cached = _CACHE.get(cache_key)
    if cached is not None:
        return cached

    # Instantiate embedder
    embedder = TextEmbedder(model_name=m_name, device=dev)
    # Trigger lazy loading of underlying model once
    _ = embedder.model
    _CACHE.set(cache_key, embedder)
    return embedder


def get_cached_semantic_reference_index(
    ref_dir: Optional[Union[str, Path]] = None,
):
    """Retrieves or loads the singleton SemanticReferenceIndex instance."""
    from src.semantic.reference_index import SemanticReferenceIndex

    r_dir = Path(ref_dir).resolve() if ref_dir else FROZEN_CONFIG.SEMANTIC_REFERENCE_DIR.resolve()
    cache_key = f"semantic_ref_index:{r_dir}"

    cached = _CACHE.get(cache_key)
    if cached is not None:
        return cached

    # Validate artifacts before loading
    ArtifactManager.validate_semantic_reference_artifacts(r_dir)

    index = SemanticReferenceIndex.load(r_dir)
    _CACHE.set(cache_key, index)
    return index


def get_cached_knowledge_retriever(
    kb_dir: Optional[Union[str, Path]] = None,
):
    """Retrieves or loads the singleton KnowledgeRetriever instance."""
    from src.rag.retriever import KnowledgeRetriever

    k_dir = Path(kb_dir).resolve() if kb_dir else FROZEN_CONFIG.KNOWLEDGE_BASE_DIR.resolve()
    cache_key = f"knowledge_retriever:{k_dir}"

    cached = _CACHE.get(cache_key)
    if cached is not None:
        return cached

    # Validate artifacts before loading
    ArtifactManager.validate_knowledge_base_artifacts(k_dir)

    retriever = KnowledgeRetriever(kb_dir=k_dir)
    _CACHE.set(cache_key, retriever)
    return retriever


def get_cached_baseline_classifier(
    model_dir: Optional[Union[str, Path]] = None,
    threshold: Optional[float] = None,
):
    """Retrieves or loads the singleton BaselineTextClassifier instance."""
    from src.models.baseline_classifier import BaselineTextClassifier

    m_dir = Path(model_dir).resolve() if model_dir else FROZEN_CONFIG.BASELINE_MODEL_DIR.resolve()
    thresh = threshold if threshold is not None else FROZEN_CONFIG.PHASE3_BASELINE_THRESHOLD
    cache_key = f"baseline_classifier:{m_dir}:{thresh}"

    cached = _CACHE.get(cache_key)
    if cached is not None:
        return cached

    # Validate artifacts before loading
    ArtifactManager.validate_baseline_artifacts(m_dir)

    classifier = BaselineTextClassifier(model_dir=m_dir, threshold=thresh)
    _CACHE.set(cache_key, classifier)
    return classifier


def get_cached_char_classifier(
    model_dir: Optional[Union[str, Path]] = None,
    threshold: Optional[float] = None,
):
    """Retrieves or loads the singleton CharNgramClassifier (Model B) instance."""
    from src.models.phase13.char_classifier import CharNgramClassifier

    m_dir = Path(model_dir).resolve() if model_dir else FROZEN_CONFIG.PHASE13_CHAR_NGRAM_DIR.resolve()
    thresh = threshold if threshold is not None else FROZEN_CONFIG.PHASE13_MODEL_B_THRESHOLD
    cache_key = f"char_ngram_classifier:{m_dir}:{thresh}"

    cached = _CACHE.get(cache_key)
    if cached is not None:
        return cached

    # Validate artifacts before loading
    ArtifactManager.validate_phase13_char_artifacts(m_dir)

    classifier = CharNgramClassifier(
        model_dir=m_dir,
        threshold=thresh,
        ngram_range=FROZEN_CONFIG.CHAR_NGRAM_RANGE,
        max_features=FROZEN_CONFIG.CHAR_MAX_FEATURES,
    )
    _CACHE.set(cache_key, classifier)
    return classifier


def clear_model_cache() -> None:
    """Explicitly clears the global model cache."""
    _CACHE.clear()


def get_cache_stats() -> Dict[str, Any]:
    """Returns telemetry statistics from the global model cache."""
    return _CACHE.get_stats()
