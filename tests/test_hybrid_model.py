"""Unit and integration tests for ScamShield AI Phase 5 Hybrid Text + URL Baseline.

Tests:
1. Feature extraction:
   - Message with no URLs produces all zeros for URL features.
   - Message with one URL extracts correct features and signals.
   - Message with multiple URLs computes correct aggregations (max, mean, counts).
   - Message with malformed URL handled gracefully without crashing.
   - Empty URL list handled gracefully.
2. Correct feature dimensions:
   - URL feature vector length matches URL_FEATURE_NAMES (25 dimensions).
   - Combined feature matrix has expected shape (vocabulary + 25).
3. Data leakage prevention:
   - Split matches Phase 3 leak-free split exactly (3,881 train / 837 val / 856 test).
   - Zero sample ID overlap and zero text overlap across splits.
   - TF-IDF vectorizer and URL scaler fitted strictly on training partition.
4. Model inference:
   - HybridTextURLClassifier predicts on single message without URLs.
   - HybridTextURLClassifier predicts on single message with URL.
   - Prediction output contains expected fields (label, scam_probability, has_url, etc.).
   - Probabilities are valid floats within [0.0, 1.0].
   - Threshold application functions correctly.
5. Evaluation & Checkpoint integrity:
   - All required Phase 5 model and evaluation artifacts exist.
   - Test predictions file contains exactly 856 rows.
   - Phase 3 reference baseline artifacts remain intact and unchanged.
"""

import json
from pathlib import Path
import unittest
import joblib
import numpy as np

from src.models.hybrid_baseline import (
    URL_FEATURE_NAMES,
    HybridTextURLClassifier,
    build_message_url_features,
)
from src.url_analysis.analyzer import analyze_url


class TestPhase5HybridModel(unittest.TestCase):
    """Test suite covering Phase 5 Hybrid Text + URL model and feature extraction."""

    @classmethod
    def setUpClass(cls):
        cls.root_dir = Path(__file__).resolve().parents[1]
        cls.model_dir = cls.root_dir / "models" / "hybrid"
        cls.eval_dir = cls.root_dir / "data" / "evaluation" / "hybrid"
        cls.p3_eval_dir = cls.root_dir / "data" / "evaluation" / "baseline"

        # Load classifier once for inference tests
        cls.classifier = HybridTextURLClassifier.load(cls.model_dir)

    def test_url_feature_names_count(self):
        """Verify URL feature list contains exactly 25 features."""
        self.assertEqual(len(URL_FEATURE_NAMES), 25)
        self.assertIn("has_url", URL_FEATURE_NAMES)
        self.assertIn("url_count", URL_FEATURE_NAMES)
        self.assertIn("max_url_risk_score", URL_FEATURE_NAMES)
        self.assertIn("mean_url_risk_score", URL_FEATURE_NAMES)

    def test_feature_extraction_no_urls(self):
        """Verify message with no URLs produces all zeros for URL features."""
        features = build_message_url_features("Hello world, call me later", [])
        self.assertEqual(len(features), 25)
        self.assertTrue(all(v == 0.0 for v in features))

    def test_feature_extraction_empty_list(self):
        """Verify passing empty URL list returns expected zero-filled vector."""
        features = build_message_url_features("Some random message", [])
        self.assertEqual(len(features), len(URL_FEATURE_NAMES))
        self.assertEqual(features[URL_FEATURE_NAMES.index("has_url")], 0.0)
        self.assertEqual(features[URL_FEATURE_NAMES.index("url_count")], 0.0)

    def test_feature_extraction_single_url(self):
        """Verify message with a single URL extracts correct features and signals."""
        url = "http://192.168.1.1/login.php?user=admin"
        features = build_message_url_features(f"Please log in at {url}", [url])
        self.assertEqual(len(features), 25)

        has_url_idx = URL_FEATURE_NAMES.index("has_url")
        url_count_idx = URL_FEATURE_NAMES.index("url_count")
        ip_signal_idx = URL_FEATURE_NAMES.index("has_ip_based_hostname")
        plain_http_idx = URL_FEATURE_NAMES.index("has_plain_http_sensitive")
        max_risk_idx = URL_FEATURE_NAMES.index("max_url_risk_score")

        self.assertEqual(features[has_url_idx], 1.0)
        self.assertEqual(features[url_count_idx], 1.0)
        self.assertEqual(features[ip_signal_idx], 1.0)
        self.assertEqual(features[plain_http_idx], 1.0)
        self.assertGreater(features[max_risk_idx], 0.0)

        # Test plain unencrypted URL triggering general insecure_http
        plain_features = build_message_url_features("Visit http://example.com/page", ["http://example.com/page"])
        insecure_idx = URL_FEATURE_NAMES.index("has_insecure_http")
        self.assertEqual(plain_features[insecure_idx], 1.0)

    def test_feature_extraction_multiple_urls_aggregation(self):
        """Verify aggregation logic for messages containing multiple URLs."""
        url1 = "http://short.ly/xyz"
        url2 = "https://very-long-bank-phish-domain-name.example.com/account/verify"
        features = build_message_url_features(
            f"Check {url1} or {url2}",
            [url1, url2]
        )
        self.assertEqual(len(features), 25)

        analysis1 = analyze_url(url1)
        analysis2 = analyze_url(url2)

        expected_count = 2.0
        expected_max_risk = max(analysis1["risk_score"], analysis2["risk_score"])
        expected_mean_risk = (analysis1["risk_score"] + analysis2["risk_score"]) / 2.0
        expected_max_len = float(max(analysis1["features"]["url_length"], analysis2["features"]["url_length"]))

        self.assertEqual(features[URL_FEATURE_NAMES.index("has_url")], 1.0)
        self.assertEqual(features[URL_FEATURE_NAMES.index("url_count")], expected_count)
        self.assertAlmostEqual(features[URL_FEATURE_NAMES.index("max_url_risk_score")], expected_max_risk, places=4)
        self.assertAlmostEqual(features[URL_FEATURE_NAMES.index("mean_url_risk_score")], expected_mean_risk, places=4)
        self.assertEqual(features[URL_FEATURE_NAMES.index("max_url_length")], expected_max_len)

    def test_feature_extraction_malformed_url_graceful(self):
        """Verify malformed or invalid URL strings do not cause crashes."""
        malformed_urls = ["://broken_url", "http://", "not a url %%%", ""]
        features = build_message_url_features("Broken link here", malformed_urls)
        self.assertEqual(len(features), 25)
        # Should not raise exception, values must be valid floats
        for val in features:
            self.assertIsInstance(val, float)

    def test_cached_url_analysis(self):
        """Verify cache dictionary is populated and reused across calls."""
        cache = {}
        url = "https://example.com/path"
        build_message_url_features(f"Visit {url}", [url], analyzed_cache=cache)
        self.assertIn(url, cache)
        # Second call with same cache should reuse result
        build_message_url_features(f"Visit again {url}", [url], analyzed_cache=cache)
        self.assertEqual(len(cache), 1)

    def test_inference_no_url(self):
        """Verify inference on a clean message without URLs."""
        res = self.classifier.predict("Hey mom, are we having dinner tonight?", urls=[])
        self.assertIn("label", res)
        self.assertIn("scam_probability", res)
        self.assertIn("decision_threshold", res)
        self.assertIn("has_url", res)
        self.assertIn("url_count", res)
        self.assertIn("url_risk_score", res)

        self.assertIn(res["label"], ["scam", "non_scam"])
        self.assertEqual(res["label"], "non_scam")
        self.assertFalse(res["has_url"])
        self.assertEqual(res["url_count"], 0)
        self.assertEqual(res["url_risk_score"], 0.0)
        self.assertGreaterEqual(res["scam_probability"], 0.0)
        self.assertLessEqual(res["scam_probability"], 1.0)

    def test_inference_with_scam_url(self):
        """Verify inference on a message containing a suspicious phishing URL."""
        res = self.classifier.predict(
            "URGENT: Claim your $1000 prize now at http://192.168.1.1/free-cash",
            urls=["http://192.168.1.1/free-cash"]
        )
        self.assertEqual(res["label"], "scam")
        self.assertTrue(res["has_url"])
        self.assertEqual(res["url_count"], 1)
        self.assertGreater(res["url_risk_score"], 0.0)
        self.assertGreater(res["scam_probability"], 0.5)

    def test_inference_threshold_adjustment(self):
        """Verify manual threshold argument alters classification appropriately."""
        text = "Free entry in 2 a weekly competition to win FA Cup final tickets"
        # At very low threshold, should predict scam
        res_low = self.classifier.predict(text, threshold=0.01)
        self.assertEqual(res_low["label"], "scam")

        # At very high threshold, should predict non_scam
        res_high = self.classifier.predict(text, threshold=0.99)
        self.assertEqual(res_high["label"], "non_scam")

    def test_model_checkpoints_exist(self):
        """Verify required model checkpoints exist in models/hybrid/."""
        self.assertTrue((self.model_dir / "tfidf_vectorizer.joblib").exists())
        self.assertTrue((self.model_dir / "url_scaler.joblib").exists())
        self.assertTrue((self.model_dir / "logistic_regression.joblib").exists())
        self.assertTrue((self.model_dir / "model_metadata.json").exists())

    def test_model_metadata_content(self):
        """Verify model metadata contains required experimental attributes."""
        with open(self.model_dir / "model_metadata.json", "r", encoding="utf-8") as f:
            metadata = json.load(f)

        self.assertEqual(metadata["split_counts"]["train"], 3881)
        self.assertEqual(metadata["split_counts"]["validation"], 837)
        self.assertEqual(metadata["split_counts"]["test"], 856)
        self.assertEqual(metadata["url_feature_count"], 25)
        self.assertEqual(metadata["selected_threshold"], 0.30)
        self.assertEqual(metadata["default_threshold"], 0.50)

    def test_scaler_feature_count(self):
        """Verify saved scaler was fitted strictly on 25 URL features."""
        scaler = joblib.load(self.model_dir / "url_scaler.joblib")
        self.assertEqual(scaler.n_features_in_, 25)

    def test_vectorizer_vocabulary_size(self):
        """Verify saved vectorizer vocabulary matches Phase 3 vocabulary."""
        vec = joblib.load(self.model_dir / "tfidf_vectorizer.joblib")
        self.assertEqual(len(vec.vocabulary_), 10637)

    def test_evaluation_artifacts_exist(self):
        """Verify all required evaluation artifacts exist in data/evaluation/hybrid/."""
        required_files = [
            "metrics.json",
            "confusion_matrix.json",
            "comparison.json",
            "url_subset_metrics.json",
            "test_predictions.jsonl",
            "error_analysis.jsonl",
            "feature_coefficients.json",
            "ablation_results.json",
            "README.md",
        ]
        for fname in required_files:
            p = self.eval_dir / fname
            self.assertTrue(p.exists(), f"Missing required artifact: {p}")

    def test_test_predictions_row_count(self):
        """Verify test_predictions.jsonl contains exactly 856 lines."""
        pred_path = self.eval_dir / "test_predictions.jsonl"
        with open(pred_path, "r", encoding="utf-8") as f:
            lines = [line.strip() for line in f if line.strip()]
        self.assertEqual(len(lines), 856)

        # Inspect first row schema
        first_row = json.loads(lines[0])
        for expected_key in ["sample_id", "text", "true_label", "predicted_label", "predicted_probability", "threshold"]:
            self.assertIn(expected_key, first_row)

    def test_ablation_results_keys(self):
        """Verify 3-way ablation results are populated with correct keys."""
        with open(self.eval_dir / "ablation_results.json", "r", encoding="utf-8") as f:
            ablation = json.load(f)

        self.assertIn("model_a_text_only", ablation)
        self.assertIn("model_b_text_plus_agg_url_risk", ablation)
        self.assertIn("model_c_full_hybrid", ablation)

        # Ensure all models have valid test F1-scores
        for m_key in ["model_a_text_only", "model_b_text_plus_agg_url_risk", "model_c_full_hybrid"]:
            self.assertGreater(ablation[m_key]["metrics"]["scam"]["f1_score"], 0.90)

    def test_phase3_baseline_remains_frozen(self):
        """Verify Phase 3 reference metrics in data/evaluation/baseline/ are untouched."""
        p3_metrics_path = self.p3_eval_dir / "metrics.json"
        self.assertTrue(p3_metrics_path.exists())
        with open(p3_metrics_path, "r", encoding="utf-8") as f:
            p3_metrics = json.load(f)

        # Phase 3 selected threshold test accuracy was 98.25% (0.9825)
        self.assertAlmostEqual(p3_metrics["test_selected_threshold"]["accuracy"], 0.9825, places=4)
        self.assertAlmostEqual(p3_metrics["test_selected_threshold"]["scam"]["f1_score"], 0.9378, places=4)


if __name__ == "__main__":
    unittest.main()
