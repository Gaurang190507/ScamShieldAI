"""Unit tests for ScamShield AI Phase 9B supervised visual classifier."""

import tempfile
import unittest
from pathlib import Path
from PIL import Image

from src.vision.schemas import VisualFeatures, VisualSampleRecord
from src.vision.visual_classifier import VisualScamClassifier
from src.vision.visual_predictor import VisualPredictor


def create_dummy_features(is_scam: bool) -> VisualFeatures:
    """Creates synthetic features with distinct patterns for testing."""
    return VisualFeatures(
        width=400,
        height=500,
        aspect_ratio=0.8,
        mean_brightness=200.0 if not is_scam else 150.0,
        std_brightness=30.0 if not is_scam else 60.0,
        entropy=4.0 if not is_scam else 6.5,
        whitespace_ratio=0.7 if not is_scam else 0.2,
        mean_red=150.0 if not is_scam else 220.0,
        mean_green=180.0 if not is_scam else 100.0,
        mean_blue=190.0 if not is_scam else 110.0,
        red_ratio=0.28 if not is_scam else 0.51,
        mean_saturation=0.2 if not is_scam else 0.6,
        color_variance=10.0 if not is_scam else 40.0,
        edge_density=0.08 if not is_scam else 0.35,
        top_luminance_ratio=1.0 if not is_scam else 1.4,
        bottom_luminance_ratio=1.0 if not is_scam else 0.8,
        horizontal_asymmetry=5.0 if not is_scam else 15.0,
        header_banner_detected=is_scam,
        button_candidate_count=0 if not is_scam else 2,
        qr_candidate_detected=is_scam,
    )


class TestVisualClassifier(unittest.TestCase):
    """Verifies train-only fitting, validation tuning, and prediction behavior."""

    def setUp(self):
        self.train_data = [
            (create_dummy_features(is_scam=False), "non_scam") for _ in range(10)
        ] + [
            (create_dummy_features(is_scam=True), "scam") for _ in range(8)
        ]
        self.val_data = [
            (create_dummy_features(is_scam=False), "non_scam") for _ in range(4)
        ] + [
            (create_dummy_features(is_scam=True), "scam") for _ in range(4)
        ]

    def test_classifier_fit_and_predict(self):
        """Classifier must fit on training features and output calibrated probabilities."""
        clf = VisualScamClassifier()
        self.assertFalse(clf.is_fitted)

        clf.fit(self.train_data)
        self.assertTrue(clf.is_fitted)

        # Test prediction on dummy features
        scam_feat = create_dummy_features(is_scam=True)
        prob = clf.predict_proba(scam_feat)
        self.assertGreaterEqual(prob, 0.0)
        self.assertLessEqual(prob, 1.0)

        label, _ = clf.predict(scam_feat)
        self.assertIn(label, ["scam", "non_scam"])

    def test_validation_threshold_tuning(self):
        """Threshold tuning on validation data updates decision boundary."""
        clf = VisualScamClassifier()
        clf.fit(self.train_data)
        initial_thresh = clf.threshold

        tuned_thresh = clf.tune_threshold(self.val_data)
        self.assertTrue(clf.threshold_tuned)
        self.assertGreaterEqual(tuned_thresh, 0.0)
        self.assertLessEqual(tuned_thresh, 1.0)

    def test_leakage_protection_on_fit(self):
        """Attempting to fit on records with split != 'train' must raise ValueError."""
        leaked_record = VisualSampleRecord(
            image_id="leak_01",
            image_path="dummy.png",
            label="scam",
            source_type="synthetic",
            scenario="test",
            pattern_group_id="group_x",
            split="test",  # Leaked test record!
        )
        clf = VisualScamClassifier()
        with self.assertRaises(ValueError) as ctx:
            clf.fit([leaked_record])
        self.assertIn("CRITICAL LEAKAGE ATTEMPT", str(ctx.exception))

    def test_leakage_protection_on_tune_threshold(self):
        """Attempting to tune threshold on records with split != 'val' must raise ValueError."""
        clf = VisualScamClassifier()
        clf.fit(self.train_data)

        leaked_record = VisualSampleRecord(
            image_id="leak_02",
            image_path="dummy.png",
            label="scam",
            source_type="synthetic",
            scenario="test",
            pattern_group_id="group_x",
            split="train",  # Leaked train record in val!
        )
        with self.assertRaises(ValueError) as ctx:
            clf.tune_threshold([leaked_record])
        self.assertIn("CRITICAL LEAKAGE ATTEMPT", str(ctx.exception))

    def test_feature_importance_coefficients(self):
        """Fitted classifier exposes coefficients for all 20 features."""
        clf = VisualScamClassifier()
        clf.fit(self.train_data)
        importances = clf.get_feature_importances()

        self.assertEqual(len(importances), 20)
        for name in VisualFeatures.feature_names():
            self.assertIn(name, importances)

    def test_serialization_and_save(self):
        """Classifier state serializes to dictionary and saves cleanly to JSON."""
        clf = VisualScamClassifier()
        clf.fit(self.train_data)
        d = clf.to_dict()

        self.assertTrue(d["is_fitted"])
        self.assertEqual(len(d["coefficients"]), 20)

        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as tmp:
            tmp_path = Path(tmp.name)
        try:
            clf.save(tmp_path)
            self.assertTrue(tmp_path.is_file())
            self.assertGreater(tmp_path.stat().st_size, 0)
        finally:
            if tmp_path.is_file():
                tmp_path.unlink()

    def test_predictor_service_integration(self):
        """VisualPredictor packages features, evidence, and prediction."""
        clf = VisualScamClassifier()
        clf.fit(self.train_data)
        predictor = VisualPredictor(clf)

        img = Image.new("RGB", (200, 200), color=(255, 255, 255))
        result = predictor.predict_image(img, image_id="test_img")

        self.assertEqual(result.image_id, "test_img")
        self.assertIn(result.predicted_label, ["scam", "non_scam"])
        self.assertGreaterEqual(result.probability, 0.0)
        self.assertLessEqual(result.probability, 1.0)
        self.assertTrue(result.audit["offline_execution"])


if __name__ == "__main__":
    unittest.main()
