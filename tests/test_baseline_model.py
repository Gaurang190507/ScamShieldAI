"""Unit tests for ScamShield AI Phase 3 ML baseline pipeline and prediction interface.

Tests:
1. Dataset loads correctly.
2. Labels contain only canonical values.
3. Train/validation/test IDs do not overlap.
4. TF-IDF is fitted only on training data.
5. Training produces a fitted model.
6. Prediction returns the expected structured format.
7. Probability is within [0, 1].
8. Prediction label is one of ('scam', 'non_scam').
9. Saved model artifacts can be loaded cleanly.
10. Evaluation metrics are generated with valid numeric scores.
11. Error analysis contains only test-set sample IDs.
12. No test labels or data are used during model fitting.
"""

import json
from pathlib import Path
import unittest
import numpy as np
import pandas as pd
import joblib

from src.data.dataset_schema import Label
from src.data.leakage_split import group_leakage_split, verify_no_group_leakage
from src.models.baseline_classifier import BaselineTextClassifier, predict
from src.models.train_baseline import compute_binary_metrics


class TestPhase3BaselineModel(unittest.TestCase):
    """Test suite covering Phase 3 baseline text classifier and artifacts."""

    @classmethod
    def setUpClass(cls):
        cls.root_dir = Path(__file__).resolve().parents[1]
        cls.dataset_path = cls.root_dir / "data" / "processed" / "preprocessed" / "uci_sms_spam.jsonl"
        cls.models_dir = cls.root_dir / "models" / "baseline"
        cls.eval_dir = cls.root_dir / "data" / "evaluation" / "baseline"

        if not cls.dataset_path.is_file():
            raise FileNotFoundError(f"Dataset missing: {cls.dataset_path}")

        with open(cls.dataset_path, "r", encoding="utf-8") as f:
            cls.records = [json.loads(line) for line in f]

        cls.df = pd.DataFrame(cls.records)

    def test_01_dataset_loads_correctly(self):
        """Test 1: Preprocessed dataset loads with expected shape and non-empty rows."""
        self.assertEqual(len(self.df), 5574)
        self.assertIn("text", self.df.columns)
        self.assertIn("label", self.df.columns)
        self.assertIn("sample_id", self.df.columns)
        self.assertFalse(self.df["text"].isna().any())

    def test_02_labels_contain_only_canonical_values(self):
        """Test 2: Target labels contain exclusively canonical Label enum values."""
        unique_labels = set(self.df["label"].unique())
        allowed_labels = {Label.SCAM.value, Label.NON_SCAM.value}
        self.assertTrue(
            unique_labels.issubset(allowed_labels),
            f"Non-canonical labels found: {unique_labels - allowed_labels}",
        )
        self.assertEqual(unique_labels, allowed_labels)

    def test_03_split_ids_do_not_overlap(self):
        """Test 3: Train, validation, and test sample IDs and pattern groups are mutually disjoint."""
        self.df["_grp"] = self.df["pattern_group_id"].fillna(self.df["sample_id"])
        train_df, val_df, test_df = group_leakage_split(
            self.df, group_col="_grp", test_size=0.15, val_size=0.15, random_state=42
        )

        train_ids = set(train_df["sample_id"])
        val_ids = set(val_df["sample_id"])
        test_ids = set(test_df["sample_id"])

        self.assertEqual(len(train_ids.intersection(val_ids)), 0)
        self.assertEqual(len(train_ids.intersection(test_ids)), 0)
        self.assertEqual(len(val_ids.intersection(test_ids)), 0)
        self.assertEqual(len(train_ids) + len(val_ids) + len(test_ids), len(self.df))

        is_leak_free, msg = verify_no_group_leakage(train_df, val_df, test_df, group_col="_grp")
        self.assertTrue(is_leak_free, msg)

    def test_04_tfidf_fitted_only_on_training_data(self):
        """Test 4: Verify that TF-IDF vectorizer reflects only training vocabulary."""
        meta_file = self.models_dir / "model_metadata.json"
        self.assertTrue(meta_file.is_file(), "model_metadata.json missing")
        with open(meta_file, "r", encoding="utf-8") as f:
            meta = json.load(f)

        vec_file = self.models_dir / "tfidf_vectorizer.joblib"
        self.assertTrue(vec_file.is_file(), "tfidf_vectorizer.joblib missing")
        vectorizer = joblib.load(vec_file)

        # Check that vocabulary matches training set recorded count
        self.assertEqual(len(vectorizer.vocabulary_), meta["vocabulary_size"])

    def test_05_training_produces_fitted_model(self):
        """Test 5: Serialized Logistic Regression model has fitted coefficients."""
        clf_file = self.models_dir / "logistic_regression.joblib"
        self.assertTrue(clf_file.is_file(), "logistic_regression.joblib missing")
        clf = joblib.load(clf_file)

        self.assertTrue(hasattr(clf, "coef_"))
        self.assertTrue(hasattr(clf, "intercept_"))
        self.assertEqual(len(clf.classes_), 2)

    def test_06_prediction_returns_expected_format(self):
        """Test 6: Inference returns structured dictionary with required keys."""
        res = predict("Claim your prize now! Call 0800123456.")
        self.assertIsInstance(res, dict)
        expected_keys = {"label", "probability", "threshold", "scam_probability", "non_scam_probability"}
        self.assertTrue(expected_keys.issubset(set(res.keys())))

    def test_07_probability_within_valid_bounds(self):
        """Test 7: Predicted probability is strictly between 0.0 and 1.0."""
        texts = [
            "Normal conversation with a colleague.",
            "URGENT: Your account has been suspended! Click http://fake.com",
            "",
            "123456",
        ]
        for t in texts:
            res = predict(t)
            self.assertGreaterEqual(res["probability"], 0.0)
            self.assertLessEqual(res["probability"], 1.0)
            self.assertGreaterEqual(res["scam_probability"], 0.0)
            self.assertLessEqual(res["scam_probability"], 1.0)
            self.assertGreaterEqual(res["non_scam_probability"], 0.0)
            self.assertLessEqual(res["non_scam_probability"], 1.0)
            self.assertAlmostEqual(res["scam_probability"] + res["non_scam_probability"], 1.0, places=3)

    def test_08_prediction_label_is_canonical(self):
        """Test 8: Output label is either 'scam' or 'non_scam'."""
        res_scam = predict("WINNER! You have won £1,000 cash. Call 09050000327.")
        res_ham = predict("Are you free to meet for coffee later?")

        self.assertIn(res_scam["label"], ["scam", "non_scam"])
        self.assertIn(res_ham["label"], ["scam", "non_scam"])
        self.assertEqual(res_scam["label"], "scam")
        self.assertEqual(res_ham["label"], "non_scam")

    def test_09_saved_model_artifacts_can_be_loaded(self):
        """Test 9: BaselineTextClassifier can initialize and load artifacts from models directory."""
        classifier = BaselineTextClassifier(model_dir=self.models_dir)
        self.assertIsNotNone(classifier.vectorizer)
        self.assertIsNotNone(classifier.classifier)
        self.assertGreater(classifier.threshold, 0.0)

    def test_10_evaluation_metrics_are_generated(self):
        """Test 10: Evaluation metrics JSON contains valid accuracy, precision, recall, and F1."""
        metrics_file = self.eval_dir / "metrics.json"
        self.assertTrue(metrics_file.is_file(), "metrics.json missing")
        with open(metrics_file, "r", encoding="utf-8") as f:
            metrics = json.load(f)

        self.assertIn("test_selected_threshold", metrics)
        test_m = metrics["test_selected_threshold"]

        self.assertGreater(test_m["accuracy"], 0.90)
        self.assertGreater(test_m["roc_auc"], 0.90)
        self.assertGreater(test_m["scam"]["precision"], 0.85)
        self.assertGreater(test_m["scam"]["recall"], 0.70)
        self.assertGreater(test_m["scam"]["f1_score"], 0.80)

    def test_11_error_analysis_contains_only_test_samples(self):
        """Test 11: Error analysis entries strictly belong to the test partition."""
        error_file = self.eval_dir / "error_analysis.jsonl"
        self.assertTrue(error_file.is_file(), "error_analysis.jsonl missing")

        # Load test partition IDs
        preds_file = self.eval_dir / "test_predictions.jsonl"
        self.assertTrue(preds_file.is_file(), "test_predictions.jsonl missing")

        test_ids = set()
        with open(preds_file, "r", encoding="utf-8") as f:
            for line in f:
                rec = json.loads(line)
                test_ids.add(rec["sample_id"])

        self.assertEqual(len(test_ids), 856)

        with open(error_file, "r", encoding="utf-8") as f:
            for line in f:
                rec = json.loads(line)
                self.assertIn(
                    rec["sample_id"],
                    test_ids,
                    f"Error sample {rec['sample_id']} not found in test predictions!",
                )
                self.assertIn(rec["error_type"], ["false_positive", "false_negative"])
                self.assertNotEqual(rec["true_label"], rec["predicted_label"])

    def test_12_no_test_labels_used_during_training(self):
        """Test 12: Ensure split sizes strictly match train/val/test and no test records entered train."""
        meta_file = self.models_dir / "model_metadata.json"
        with open(meta_file, "r", encoding="utf-8") as f:
            meta = json.load(f)

        split_counts = meta["split_counts"]
        self.assertEqual(split_counts["train"], 3881)
        self.assertEqual(split_counts["validation"], 837)
        self.assertEqual(split_counts["test"], 856)
        self.assertEqual(
            split_counts["train"] + split_counts["validation"] + split_counts["test"], 5574
        )


if __name__ == "__main__":
    unittest.main()
