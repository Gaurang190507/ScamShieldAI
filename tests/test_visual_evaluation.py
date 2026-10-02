"""Unit tests for Phase 9B evaluation experiments and multimodal fusion."""

import json
from pathlib import Path
import unittest

from src.vision.evaluate_visual import compute_binary_metrics, run_phase9b_experiments
from src.vision.schemas import CombinedPredictionResult


class TestVisualEvaluation(unittest.TestCase):
    """Verifies controlled experiment execution, metrics calculation, and report creation."""

    def test_compute_binary_metrics(self):
        """Standard metrics calculation handles balanced, edge, and empty cases."""
        y_true = [1, 1, 0, 0]
        y_pred = [1, 0, 0, 0]
        y_probs = [0.9, 0.4, 0.1, 0.2]

        m = compute_binary_metrics(y_true, y_pred, y_probs)
        self.assertEqual(m["accuracy"], 0.75)
        self.assertEqual(m["recall"], 0.50)
        self.assertEqual(m["precision"], 1.0)
        self.assertAlmostEqual(m["f1"], 0.6667, places=3)
        self.assertGreater(m["roc_auc"], 0.5)

    def test_run_phase9b_experiments_end_to_end(self):
        """End-to-end evaluation produces complete report bundle and valid metrics."""
        manifest_p = Path("data/visual/metadata/dataset_manifest.json")
        self.assertTrue(manifest_p.is_file(), "Manifest must exist before running evaluation tests.")

        output_dir = Path("data/evaluation/visual")
        results = run_phase9b_experiments(manifest_path=manifest_p, output_dir=output_dir)

        # Structure checks
        self.assertIn("experiments", results)
        self.assertIn("hard_negative_analysis", results)
        self.assertIn("complementarity", results)
        self.assertIn("paired_variations", results)

        # Experiment metrics exist
        for exp_key in ["experiment_a_text_only", "experiment_b_visual_only", "experiment_c_multimodal_fusion"]:
            self.assertIn(exp_key, results["experiments"])
            exp = results["experiments"][exp_key]
            for metric in ["accuracy", "precision", "recall", "f1", "roc_auc"]:
                self.assertIn(metric, exp)
                self.assertGreaterEqual(exp[metric], 0.0)
                self.assertLessEqual(exp[metric], 1.0)

        # Hard negative metrics
        hn = results["hard_negative_analysis"]
        self.assertGreater(hn["total_hard_negatives"], 0)
        self.assertGreaterEqual(hn["visual_false_positives"], 0)

        # Markdown reports created
        self.assertTrue((output_dir / "phase9b_visual_evaluation.md").is_file())
        self.assertTrue((output_dir / "visual_hard_negative_analysis.md").is_file())
        self.assertTrue((output_dir / "evaluation_results.json").is_file())


if __name__ == "__main__":
    unittest.main()
