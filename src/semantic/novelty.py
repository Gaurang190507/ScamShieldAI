"""Novelty detection and pattern interpretation for ScamShield AI.

Important Architectural Distinction:
====================================
NOVELTY != SCAM.
A semantically novel message is simply one that exhibits low similarity to
patterns present in the known reference training corpus.
A novel message may be:
- A completely benign message discussing an unusual topic.
- A legitimate new administrative notification.
- An unusual conversational exchange.
- A genuinely emerging, previously unseen scam pattern.

Therefore, semantic novelty provides an evidentiary signal of divergence
from known reference data, NOT a scam verdict or classification probability.
"""

from typing import Tuple
import numpy as np


class NoveltyDetector:
    """Computes relative semantic novelty score and status against a reference corpus."""

    # Provisional operational boundaries used for Phase 7 exploratory categorization
    DEFAULT_KNOWN_SIMILARITY_THRESHOLD = 0.70
    DEFAULT_NOVEL_SIMILARITY_THRESHOLD = 0.50

    def __init__(
        self,
        known_threshold: float = DEFAULT_KNOWN_SIMILARITY_THRESHOLD,
        novel_threshold: float = DEFAULT_NOVEL_SIMILARITY_THRESHOLD,
    ):
        """Initializes detector with provisional operational similarity boundaries.

        Args:
            known_threshold: Similarity score above which a pattern is deemed 'similar_to_known'.
            novel_threshold: Similarity score below which a pattern is deemed 'potentially_novel'.
        """
        if known_threshold < novel_threshold:
            raise ValueError(
                f"known_threshold ({known_threshold}) must be >= novel_threshold ({novel_threshold})"
            )
        self.known_threshold = known_threshold
        self.novel_threshold = novel_threshold

    @staticmethod
    def compute_novelty_score(top_1_similarity: float) -> float:
        """Calculates the uncalibrated semantic novelty score.

        Definition:
            semantic_novelty_score = 1.0 - top_1_similarity

        For unit-normalized vectors:
        - If top_1_sim == 1.0 (exact semantic duplicate): novelty = 0.0
        - If top_1_sim == 0.70 (typical close match): novelty = 0.30
        - If top_1_sim <= 0.0 (orthogonal/unrelated): novelty >= 1.0

        Args:
            top_1_similarity: Cosine similarity of the nearest neighbor in [-1.0, 1.0].

        Returns:
            Novelty score clamped to [0.0, 2.0].
        """
        if np.isnan(top_1_similarity):
            return 1.0
        clamped_sim = float(np.clip(top_1_similarity, -1.0, 1.0))
        novelty = 1.0 - clamped_sim
        return float(np.clip(novelty, 0.0, 2.0))

    def determine_status(self, top_1_similarity: float) -> str:
        """Determines categorical semantic status from top-1 similarity score.

        Categories:
        - 'similar_to_known': top_1_similarity >= known_threshold
        - 'moderately_novel': novel_threshold <= top_1_similarity < known_threshold
        - 'potentially_novel': top_1_similarity < novel_threshold

        Args:
            top_1_similarity: Nearest neighbor similarity score.

        Returns:
            Status string.
        """
        if np.isnan(top_1_similarity):
            return "potentially_novel"

        if top_1_similarity >= self.known_threshold:
            return "similar_to_known"
        elif top_1_similarity >= self.novel_threshold:
            return "moderately_novel"
        else:
            return "potentially_novel"

    def analyze(self, top_1_similarity: float) -> Tuple[float, str]:
        """Calculates both novelty score and semantic status.

        Args:
            top_1_similarity: Nearest neighbor similarity score.

        Returns:
            Tuple of (semantic_novelty_score, semantic_status).
        """
        score = self.compute_novelty_score(top_1_similarity)
        status = self.determine_status(top_1_similarity)
        return score, status
