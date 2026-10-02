"""Semantic similarity and novelty analyzer orchestrator for ScamShield AI.

Coordinates:
- TextEmbedder (inference)
- SemanticReferenceIndex (top-K retrieval)
- NoveltyDetector (relative novelty evaluation)
Produces structured, standardized SemanticResult objects adhering to the canonical schema.
"""

from typing import Any, Dict, List, Optional
import numpy as np

from .embedder import TextEmbedder
from .novelty import NoveltyDetector
from .reference_index import SemanticReferenceIndex
from .schemas import NeighborResult, SemanticAnalysis, SemanticResult


class SemanticAnalyzer:
    """End-to-end coordinator for semantic similarity search and novelty analysis."""

    def __init__(
        self,
        reference_index: SemanticReferenceIndex,
        embedder: Optional[TextEmbedder] = None,
        novelty_detector: Optional[NoveltyDetector] = None,
    ):
        """Initializes analyzer with reference index, embedder, and novelty detector.

        Args:
            reference_index: Populated SemanticReferenceIndex (from TRAIN split).
            embedder: Optional TextEmbedder. Defaults to standard all-MiniLM-L6-v2 embedder.
            novelty_detector: Optional NoveltyDetector. Defaults to standard provisional operational thresholds.
        """
        self.index = reference_index
        self.embedder = embedder or TextEmbedder(model_name=reference_index.model_name)
        self.novelty = novelty_detector or NoveltyDetector()

    def analyze(
        self,
        text: str,
        sample_id: Optional[str] = None,
        top_k: int = 5,
        disallow_same_id: bool = True,
    ) -> SemanticResult:
        """Analyzes a single text string against the known reference corpus.

        Args:
            text: Input message text.
            sample_id: Optional sample identifier for the query.
            top_k: Number of nearest reference examples to retrieve.
            disallow_same_id: If True, asserts sample_id is NOT in the reference index.

        Returns:
            Structured SemanticResult object.
        """
        clean_text = text if isinstance(text, str) else ""

        # Generate query embedding
        query_vec = self.embedder.embed_text(clean_text)

        # Retrieve nearest neighbors
        neighbors = self.index.search(
            query_vector=query_vec,
            top_k=top_k,
            query_sample_id=sample_id,
            disallow_same_id=disallow_same_id,
        )

        # Compute summary metrics
        if neighbors:
            sims = [n.similarity for n in neighbors]
            top_1_sim = sims[0]
            top_3_max = max(sims[:3]) if len(sims) >= 3 else sims[0]
            top_5_max = max(sims)
            top_5_mean = float(np.mean(sims))

            scam_sims = [n.similarity for n in neighbors if n.label == "scam"]
            non_scam_sims = [n.similarity for n in neighbors if n.label == "non_scam"]

            scam_count = len(scam_sims)
            non_scam_count = len(non_scam_sims)
            nearest_scam = max(scam_sims) if scam_sims else None
            nearest_non = max(non_scam_sims) if non_scam_sims else None
        else:
            top_1_sim = 0.0
            top_3_max = 0.0
            top_5_max = 0.0
            top_5_mean = 0.0
            scam_count = 0
            non_scam_count = 0
            nearest_scam = None
            nearest_non = None

        # Compute novelty score and status
        novelty_score, status = self.novelty.analyze(top_1_sim)

        analysis = SemanticAnalysis(
            embedding_model=self.embedder.model_name,
            embedding_dimension=self.embedder.dimension,
            top_k=top_k,
            top_1_similarity=top_1_sim,
            top_3_max_similarity=top_3_max,
            top_5_max_similarity=top_5_max,
            top_5_mean_similarity=top_5_mean,
            top_5_scam_count=scam_count,
            top_5_non_scam_count=non_scam_count,
            nearest_scam_similarity=nearest_scam,
            nearest_non_scam_similarity=nearest_non,
            semantic_novelty_score=novelty_score,
            semantic_status=status,
        )

        return SemanticResult(
            sample_id=sample_id,
            text=clean_text,
            semantic=analysis,
            neighbors=neighbors,
        )

    def analyze_batch(
        self,
        records: List[Dict[str, Any]],
        text_field: str = "text",
        id_field: str = "sample_id",
        top_k: int = 5,
        disallow_same_id: bool = True,
        batch_size: int = 64,
        show_progress: bool = False,
    ) -> List[SemanticResult]:
        """Analyzes a batch of sample records efficiently.

        Args:
            records: List of sample dictionaries.
            text_field: Key containing the message text.
            id_field: Key containing the sample ID.
            top_k: Number of nearest neighbors per query.
            disallow_same_id: If True, asserts no query sample ID is in reference index.
            batch_size: Batch size for embedding inference.
            show_progress: Whether to show progress bar.

        Returns:
            List of SemanticResult objects.
        """
        if not records:
            return []

        texts = [str(r.get(text_field, "")) for r in records]
        sample_ids = [r.get(id_field) for r in records]

        # Batch encode queries
        query_vectors = self.embedder.embed_batch(
            texts=texts,
            batch_size=batch_size,
            show_progress_bar=show_progress,
        )

        # Batch nearest-neighbor retrieval
        batch_neighbors = self.index.search_batch(
            query_vectors=query_vectors,
            top_k=top_k,
            query_sample_ids=sample_ids,
            disallow_same_id=disallow_same_id,
        )

        results: List[SemanticResult] = []
        for i, neighbors in enumerate(batch_neighbors):
            sid = sample_ids[i]
            txt = texts[i]

            if neighbors:
                sims = [n.similarity for n in neighbors]
                top_1_sim = sims[0]
                top_3_max = max(sims[:3]) if len(sims) >= 3 else sims[0]
                top_5_max = max(sims)
                top_5_mean = float(np.mean(sims))

                scam_sims = [n.similarity for n in neighbors if n.label == "scam"]
                non_scam_sims = [n.similarity for n in neighbors if n.label == "non_scam"]

                scam_count = len(scam_sims)
                non_scam_count = len(non_scam_sims)
                nearest_scam = max(scam_sims) if scam_sims else None
                nearest_non = max(non_scam_sims) if non_scam_sims else None
            else:
                top_1_sim = 0.0
                top_3_max = 0.0
                top_5_max = 0.0
                top_5_mean = 0.0
                scam_count = 0
                non_scam_count = 0
                nearest_scam = None
                nearest_non = None

            novelty_score, status = self.novelty.analyze(top_1_sim)

            analysis = SemanticAnalysis(
                embedding_model=self.embedder.model_name,
                embedding_dimension=self.embedder.dimension,
                top_k=top_k,
                top_1_similarity=top_1_sim,
                top_3_max_similarity=top_3_max,
                top_5_max_similarity=top_5_max,
                top_5_mean_similarity=top_5_mean,
                top_5_scam_count=scam_count,
                top_5_non_scam_count=non_scam_count,
                nearest_scam_similarity=nearest_scam,
                nearest_non_scam_similarity=nearest_non,
                semantic_novelty_score=novelty_score,
                semantic_status=status,
            )

            results.append(
                SemanticResult(
                    sample_id=sid,
                    text=txt,
                    semantic=analysis,
                    neighbors=neighbors,
                )
            )

        return results
