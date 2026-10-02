"""Reference corpus index and top-K semantic search for ScamShield AI.

Features:
- Encapsulates the training partition reference corpus (strictly TRAIN partition only).
- In-memory NumPy matrix cosine similarity search (fast, transparent, zero vector DB overhead).
- Strict leakage protection: prevents same-sample or duplicate queries during evaluation.
- Label-independent ranking: retrieval is strictly driven by semantic vector similarity.
- Persistent serialization and loading for reproducible evaluation.
"""

import json
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple, Union
import numpy as np

from .embedder import TextEmbedder, load_embedding_cache, save_embedding_cache
from .schemas import NeighborResult, ReferenceItem
from .similarity import compute_similarity_1d_to_2d, compute_similarity_matrix


class SemanticReferenceIndex:
    """In-memory semantic reference corpus index for top-K nearest neighbor retrieval."""

    def __init__(
        self,
        reference_items: List[ReferenceItem],
        embeddings: np.ndarray,
        model_name: str = "sentence-transformers/all-MiniLM-L6-v2",
        dimension: int = 384,
    ):
        """Initializes reference index.

        Args:
            reference_items: List of ReferenceItem metadata objects.
            embeddings: 2D numpy array of shape (N, D), float32, unit-normalized.
            model_name: HuggingFace model identifier.
            dimension: Dimensionality of embeddings.
        """
        if len(reference_items) != embeddings.shape[0]:
            raise ValueError(
                f"Mismatch: {len(reference_items)} items vs {embeddings.shape[0]} embeddings"
            )
        if embeddings.shape[1] != dimension:
            raise ValueError(
                f"Dimension mismatch: expected {dimension}, got {embeddings.shape[1]}"
            )

        self.reference_items = reference_items
        self.embeddings = embeddings.astype(np.float32)
        self.model_name = model_name
        self.dimension = dimension

        # Precompute lookup index for rapid lookup and leakage assertions
        self.sample_id_to_idx: Dict[str, int] = {
            item.sample_id: i for i, item in enumerate(self.reference_items)
        }
        self.exact_text_set: Set[str] = {item.text for item in self.reference_items}
        self.norm_text_set: Set[str] = {
            item.text.strip().lower() for item in self.reference_items
        }

    @property
    def size(self) -> int:
        """Returns the number of reference items in the index."""
        return len(self.reference_items)

    def contains_sample_id(self, sample_id: str) -> bool:
        """Checks if a sample ID exists in the reference corpus."""
        return sample_id in self.sample_id_to_idx

    def contains_exact_text(self, text: str) -> bool:
        """Checks if an exact text string exists in the reference corpus."""
        return text in self.exact_text_set

    def contains_normalized_text(self, text: str) -> bool:
        """Checks if a normalized text string exists in the reference corpus."""
        return text.strip().lower() in self.norm_text_set

    def search(
        self,
        query_vector: np.ndarray,
        top_k: int = 5,
        query_sample_id: Optional[str] = None,
        disallow_same_id: bool = True,
    ) -> List[NeighborResult]:
        """Performs top-K semantic nearest-neighbor search against the reference index.

        Args:
            query_vector: 1D query vector of shape (dimension,).
            top_k: Number of nearest neighbors to retrieve.
            query_sample_id: Optional ID of the query sample for leakage assertions.
            disallow_same_id: If True, asserts query_sample_id is NOT in reference index.

        Returns:
            List of NeighborResult objects sorted descending by similarity.
        """
        if disallow_same_id and query_sample_id and query_sample_id in self.sample_id_to_idx:
            raise ValueError(
                f"Data leakage violation: query sample_id '{query_sample_id}' exists in reference corpus!"
            )

        k = min(top_k, self.size)
        if k == 0:
            return []

        # Vector-to-matrix dot product similarity
        sims = compute_similarity_1d_to_2d(
            query=query_vector,
            ref_matrix=self.embeddings,
            assume_normalized=True,
        )

        # Get top-k indices using argpartition for O(N) selection, then sort
        if k < self.size:
            top_indices = np.argpartition(sims, -k)[-k:]
            top_indices = top_indices[np.argsort(-sims[top_indices])]
        else:
            top_indices = np.argsort(-sims)

        results: List[NeighborResult] = []
        for idx in top_indices:
            item = self.reference_items[idx]
            results.append(
                NeighborResult(
                    sample_id=item.sample_id,
                    similarity=float(sims[idx]),
                    label=item.label,
                    source=item.source,
                    text_preview=item.text_preview,
                )
            )

        return results

    def search_batch(
        self,
        query_vectors: np.ndarray,
        top_k: int = 5,
        query_sample_ids: Optional[List[str]] = None,
        disallow_same_id: bool = True,
    ) -> List[List[NeighborResult]]:
        """Performs batch top-K semantic nearest-neighbor search.

        Args:
            query_vectors: 2D query matrix of shape (M, dimension).
            top_k: Number of nearest neighbors per query.
            query_sample_ids: Optional list of query sample IDs.
            disallow_same_id: If True, asserts no query sample ID is in the reference corpus.

        Returns:
            List of lists of NeighborResult objects.
        """
        if disallow_same_id and query_sample_ids:
            for sid in query_sample_ids:
                if sid in self.sample_id_to_idx:
                    raise ValueError(
                        f"Data leakage violation: query sample_id '{sid}' exists in reference corpus!"
                    )

        k = min(top_k, self.size)
        if k == 0 or len(query_vectors) == 0:
            return [[] for _ in range(len(query_vectors))]

        sim_matrix = compute_similarity_matrix(
            queries=query_vectors,
            ref_matrix=self.embeddings,
            assume_normalized=True,
        )

        batch_results: List[List[NeighborResult]] = []
        for row in sim_matrix:
            if k < self.size:
                top_indices = np.argpartition(row, -k)[-k:]
                top_indices = top_indices[np.argsort(-row[top_indices])]
            else:
                top_indices = np.argsort(-row)

            res = [
                NeighborResult(
                    sample_id=self.reference_items[idx].sample_id,
                    similarity=float(row[idx]),
                    label=self.reference_items[idx].label,
                    source=self.reference_items[idx].source,
                    text_preview=self.reference_items[idx].text_preview,
                )
                for idx in top_indices
            ]
            batch_results.append(res)

        return batch_results

    @classmethod
    def build_from_records(
        cls,
        records: List[Dict[str, Any]],
        embedder: TextEmbedder,
        batch_size: int = 64,
        show_progress: bool = False,
    ) -> "SemanticReferenceIndex":
        """Builds a semantic reference index directly from training records.

        Args:
            records: List of sample dictionaries strictly from the TRAIN partition.
            embedder: Initialized TextEmbedder instance.
            batch_size: Batch size for embedding computation.
            show_progress: Whether to show progress bar during embedding generation.

        Returns:
            Populated SemanticReferenceIndex.
        """
        ref_items: List[ReferenceItem] = []
        texts: List[str] = []

        for idx, rec in enumerate(records):
            sid = rec.get("sample_id", f"ref_{idx}")
            txt = rec.get("text", "")
            lbl = rec.get("label", "non_scam")
            src = rec.get("source_reference") or rec.get("source_type", "unknown")
            grp = rec.get("pattern_group_id")

            # Clean preview text
            preview = (txt[:97] + "...") if len(txt) > 100 else txt

            item = ReferenceItem(
                sample_id=sid,
                label=lbl,
                text=txt,
                text_preview=preview,
                source=src,
                pattern_group_id=grp,
                embedding_idx=idx,
            )
            ref_items.append(item)
            texts.append(txt)

        embeddings = embedder.embed_batch(
            texts=texts,
            batch_size=batch_size,
            show_progress_bar=show_progress,
        )

        return cls(
            reference_items=ref_items,
            embeddings=embeddings,
            model_name=embedder.model_name,
            dimension=embedder.dimension,
        )

    def save(self, target_dir: Union[str, Path]) -> None:
        """Serializes reference metadata and embeddings to target directory.

        Args:
            target_dir: Directory to save index artifacts.
        """
        path = Path(target_dir).resolve()
        path.mkdir(parents=True, exist_ok=True)

        items_file = path / "reference_items.jsonl"
        with open(items_file, "w", encoding="utf-8") as f:
            for item in self.reference_items:
                f.write(json.dumps(item.to_dict()) + "\n")

        # Save embeddings array
        save_embedding_cache(
            save_path=path / "reference_embeddings",
            embeddings=self.embeddings,
            sample_ids=[item.sample_id for item in self.reference_items],
            metadata={
                "model_name": self.model_name,
                "dimension": self.dimension,
                "index_size": self.size,
            },
        )

    @classmethod
    def load(cls, target_dir: Union[str, Path]) -> "SemanticReferenceIndex":
        """Loads reference index from saved disk artifacts.

        Args:
            target_dir: Directory containing index artifacts.

        Returns:
            Restored SemanticReferenceIndex instance.
        """
        path = Path(target_dir).resolve()
        items_file = path / "reference_items.jsonl"
        emb_path = path / "reference_embeddings"

        if not items_file.is_file():
            raise FileNotFoundError(f"Reference items file not found: {items_file}")

        ref_items: List[ReferenceItem] = []
        with open(items_file, "r", encoding="utf-8") as f:
            for line in f:
                if line.strip():
                    d = json.loads(line)
                    ref_items.append(ReferenceItem(**d))

        embeddings, _, meta = load_embedding_cache(emb_path)

        return cls(
            reference_items=ref_items,
            embeddings=embeddings,
            model_name=meta.get("model_name", "sentence-transformers/all-MiniLM-L6-v2"),
            dimension=meta.get("dimension", 384),
        )
