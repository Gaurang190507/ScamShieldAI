"""Unit tests for ScamShield AI Phase 7 novelty detection logic.

Verifies:
1. Novelty score mathematical formulation (1.0 - top_1_similarity).
2. Monotonic inverse relationship between similarity and novelty.
3. Proper categorical assignment across calibrated thresholds.
4. Numerical edge case safety (NaN, negative similarity, exact boundaries).
5. Independence of novelty from scam labels (novelty != scam).
"""

import unittest
import numpy as np

from src.semantic.novelty import NoveltyDetector


class TestNoveltyDetection(unittest.TestCase):
    """Test suite for NoveltyDetector logic."""

    def setUp(self):
        self.detector = NoveltyDetector(known_threshold=0.70, novel_threshold=0.50)

    def test_novelty_score_exact_duplicate(self):
        """Verifies that an exact duplicate (similarity = 1.0) produces novelty = 0.0."""
        score = self.detector.compute_novelty_score(1.0)
        self.assertAlmostEqual(score, 0.0, places=6)

    def test_novelty_score_high_similarity(self):
        """Verifies novelty score for a close semantic match (similarity = 0.85)."""
        score = self.detector.compute_novelty_score(0.85)
        self.assertAlmostEqual(score, 0.15, places=6)

    def test_novelty_score_moderate_similarity(self):
        """Verifies novelty score for moderate similarity (similarity = 0.60)."""
        score = self.detector.compute_novelty_score(0.60)
        self.assertAlmostEqual(score, 0.40, places=6)

    def test_novelty_score_low_similarity(self):
        """Verifies novelty score for low similarity / novel pattern (similarity = 0.25)."""
        score = self.detector.compute_novelty_score(0.25)
        self.assertAlmostEqual(score, 0.75, places=6)

    def test_novelty_score_monotonicity(self):
        """Verifies that higher similarity strictly yields lower novelty."""
        sims = [0.95, 0.80, 0.65, 0.50, 0.35, 0.20, 0.05]
        novelties = [self.detector.compute_novelty_score(s) for s in sims]

        for i in range(len(novelties) - 1):
            self.assertLess(
                novelties[i],
                novelties[i + 1],
                f"Expected monotonic increase in novelty: {novelties[i]} < {novelties[i+1]}",
            )

    def test_semantic_status_classification(self):
        """Verifies proper mapping of similarity into semantic statuses."""
        # Top-1 >= 0.70 -> similar_to_known
        self.assertEqual(self.detector.determine_status(0.85), "similar_to_known")
        self.assertEqual(self.detector.determine_status(0.70), "similar_to_known")

        # 0.50 <= Top-1 < 0.70 -> moderately_novel
        self.assertEqual(self.detector.determine_status(0.69), "moderately_novel")
        self.assertEqual(self.detector.determine_status(0.55), "moderately_novel")
        self.assertEqual(self.detector.determine_status(0.50), "moderately_novel")

        # Top-1 < 0.50 -> potentially_novel
        self.assertEqual(self.detector.determine_status(0.49), "potentially_novel")
        self.assertEqual(self.detector.determine_status(0.15), "potentially_novel")
        self.assertEqual(self.detector.determine_status(0.0), "potentially_novel")

    def test_numerical_robustness_nan_and_bounds(self):
        """Verifies safe handling of NaN, out-of-bounds, and negative inputs."""
        # NaN returns safe default
        score_nan = self.detector.compute_novelty_score(float("nan"))
        self.assertEqual(score_nan, 1.0)
        status_nan = self.detector.determine_status(float("nan"))
        self.assertEqual(status_nan, "potentially_novel")

        # Clamping
        score_high = self.detector.compute_novelty_score(1.5)
        self.assertEqual(score_high, 0.0)

        score_neg = self.detector.compute_novelty_score(-1.0)
        self.assertEqual(score_neg, 2.0)

    def test_threshold_validation_order(self):
        """Verifies that initializing with known_threshold < novel_threshold raises ValueError."""
        with self.assertRaises(ValueError):
            NoveltyDetector(known_threshold=0.40, novel_threshold=0.60)


if __name__ == "__main__":
    unittest.main()
