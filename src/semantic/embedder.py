"""Local, deterministic text embedder using Sentence Transformers for ScamShield AI.

Implements:
- Offline embedding inference with sentence-transformers/all-MiniLM-L6-v2
- Automatic L2 unit normalization for direct dot-product cosine similarity
- Persistent binary caching (.npy) with JSON provenance metadata
"""

from datetime import datetime, timezone
import json
import os
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple, Union
import numpy as np


# Process-level model cache to prevent repeated disk weight loading
_SHARED_MODELS: Dict[Tuple[str, str], Any] = {}


def clear_shared_model_cache() -> None:
    """Clears the process-level SentenceTransformer cache."""
    _SHARED_MODELS.clear()


class TextEmbedder:
    """Encapsulates local sentence embedding model inference and normalization."""

    DEFAULT_MODEL_NAME = "sentence-transformers/all-MiniLM-L6-v2"
    DEFAULT_DIMENSION = 384

    def __init__(
        self,
        model_name: Optional[str] = None,
        normalize_embeddings: bool = True,
        device: Optional[str] = None,
    ):
        """Initializes embedder.

        Args:
            model_name: HuggingFace model identifier. Defaults to all-MiniLM-L6-v2.
            normalize_embeddings: Whether to apply L2 normalization to unit length.
            device: Computing device ('cpu', 'cuda', etc.). Defaults to CPU.
        """
        self.model_name = model_name or self.DEFAULT_MODEL_NAME
        self.normalize_embeddings = normalize_embeddings
        self.dimension = self.DEFAULT_DIMENSION
        self.device = device or "cpu"
        self._model = None

    @property
    def model(self):
        """Lazily loads or retrieves the cached local SentenceTransformer model."""
        if self._model is None:
            key = (self.model_name, self.device)
            if key in _SHARED_MODELS:
                self._model = _SHARED_MODELS[key]
                return self._model

            from sentence_transformers import SentenceTransformer

            # Attempt loading with local_files_only first to enforce offline execution
            try:
                self._model = SentenceTransformer(
                    self.model_name,
                    device=self.device,
                    local_files_only=True,
                )
            except Exception:
                # Fallback to standard loading if initial local cache lookup needs resolution
                self._model = SentenceTransformer(
                    self.model_name,
                    device=self.device,
                )
            _SHARED_MODELS[key] = self._model
        return self._model

    def embed_text(self, text: str) -> np.ndarray:
        """Generates embedding vector for a single text string.

        Args:
            text: Input string.

        Returns:
            1D numpy array of shape (384,) and dtype float32.
        """
        if not isinstance(text, str) or not text.strip():
            # For empty or whitespace text, return zero vector
            return np.zeros(self.dimension, dtype=np.float32)

        emb = self.model.encode(
            text,
            normalize_embeddings=self.normalize_embeddings,
            convert_to_numpy=True,
            show_progress_bar=False,
        )
        return emb.astype(np.float32)

    def embed_batch(
        self,
        texts: List[str],
        batch_size: int = 64,
        show_progress_bar: bool = False,
    ) -> np.ndarray:
        """Generates embedding matrix for a batch of text strings.

        Args:
            texts: List of text strings.
            batch_size: Inference batch size.
            show_progress_bar: Whether to show progress bar during batch encoding.

        Returns:
            2D numpy array of shape (len(texts), 384) and dtype float32.
        """
        if not texts:
            return np.empty((0, self.dimension), dtype=np.float32)

        cleaned_texts = [t if isinstance(t, str) and t.strip() else "" for t in texts]

        embeddings = self.model.encode(
            cleaned_texts,
            batch_size=batch_size,
            normalize_embeddings=self.normalize_embeddings,
            convert_to_numpy=True,
            show_progress_bar=show_progress_bar,
        )
        return embeddings.astype(np.float32)


def save_embedding_cache(
    save_path: Union[str, Path],
    embeddings: np.ndarray,
    sample_ids: List[str],
    metadata: Optional[Dict[str, Any]] = None,
) -> None:
    """Saves embedding array (.npy) and accompanying metadata (.json) to disk.

    Args:
        save_path: Base filepath (with or without .npy extension).
        embeddings: 2D numpy array of embeddings.
        sample_ids: List of sample IDs corresponding row-by-row to embeddings.
        metadata: Additional metadata dictionary.
    """
    base_path = Path(save_path).with_suffix("")
    base_path.parent.mkdir(parents=True, exist_ok=True)

    npy_path = base_path.with_suffix(".npy")
    json_path = base_path.with_suffix(".meta.json")

    np.save(npy_path, embeddings.astype(np.float32))

    meta = {
        "num_samples": len(sample_ids),
        "embedding_dimension": int(embeddings.shape[1]),
        "creation_date": datetime.now(timezone.utc).isoformat(),
        "sample_ids": sample_ids,
        **(metadata or {}),
    }

    with open(json_path, "w", encoding="utf-8") as f:
        json.dump(meta, f, indent=2)


def load_embedding_cache(
    save_path: Union[str, Path],
) -> Tuple[np.ndarray, List[str], Dict[str, Any]]:
    """Loads embedding array (.npy) and accompanying metadata (.json) from disk.

    Args:
        save_path: Base filepath (with or without .npy extension).

    Returns:
        Tuple of (embeddings_array, sample_ids_list, metadata_dict).
    """
    base_path = Path(save_path).with_suffix("")
    npy_path = base_path.with_suffix(".npy")
    json_path = base_path.with_suffix(".meta.json")

    if not npy_path.is_file():
        raise FileNotFoundError(f"Embedding binary cache missing: {npy_path}")
    if not json_path.is_file():
        raise FileNotFoundError(f"Embedding metadata missing: {json_path}")

    embeddings = np.load(npy_path)
    with open(json_path, "r", encoding="utf-8") as f:
        meta = json.load(f)

    sample_ids = meta.get("sample_ids", [])
    return embeddings, sample_ids, meta
