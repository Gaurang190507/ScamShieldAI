"""Unit tests for ScamShield AI Phase 9B deterministic visual feature extraction."""

import unittest
import numpy as np
from PIL import Image

from src.vision.evidence import extract_visual_evidence
from src.vision.image_features import (
    compute_edge_density,
    compute_shannon_entropy,
    count_button_candidates,
    detect_header_banner,
    detect_qr_candidate,
    extract_visual_features,
)
from src.vision.schemas import VisualEvidenceItem, VisualFeatures


class TestVisualFeatures(unittest.TestCase):
    """Test suite verifying correctness, determinism, and boundaries of visual features."""

    def setUp(self):
        # Create a synthetic test image with a header, button, and text area
        self.img = Image.new("RGB", (400, 500), color=(250, 250, 250))
        # Add a top red banner
        for y in range(60):
            for x in range(400):
                self.img.putpixel((x, y), (200, 30, 30))
        # Add a dark button near bottom
        for y in range(420, 460):
            for x in range(50, 350):
                self.img.putpixel((x, y), (30, 30, 30))

    def test_feature_extraction_dimensions_and_names(self):
        """Feature vector length must strictly match feature_names length."""
        features = extract_visual_features(self.img)
        vec = features.to_feature_vector()
        names = VisualFeatures.feature_names()

        self.assertEqual(len(vec), len(names))
        self.assertEqual(len(vec), 20)
        self.assertEqual(features.width, 400)
        self.assertEqual(features.height, 500)
        self.assertAlmostEqual(features.aspect_ratio, 0.8, places=2)

    def test_feature_determinism(self):
        """Extracting features twice from identical pixels must yield identical values."""
        f1 = extract_visual_features(self.img)
        f2 = extract_visual_features(self.img)

        self.assertEqual(f1.to_feature_vector(), f2.to_feature_vector())
        self.assertEqual(f1.to_dict(), f2.to_dict())

    def test_feature_value_ranges(self):
        """Extracted numerical metrics must satisfy valid physical and statistical bounds."""
        features = extract_visual_features(self.img)

        self.assertGreaterEqual(features.mean_brightness, 0.0)
        self.assertLessEqual(features.mean_brightness, 255.0)

        self.assertGreaterEqual(features.whitespace_ratio, 0.0)
        self.assertLessEqual(features.whitespace_ratio, 1.0)

        self.assertGreaterEqual(features.red_ratio, 0.0)
        self.assertLessEqual(features.red_ratio, 1.0)

        self.assertGreaterEqual(features.mean_saturation, 0.0)
        self.assertLessEqual(features.mean_saturation, 1.0)

        self.assertGreaterEqual(features.edge_density, 0.0)
        self.assertLessEqual(features.edge_density, 1.0)

        self.assertGreaterEqual(features.entropy, 0.0)

    def test_banner_and_button_detection(self):
        """Top banner and button should be detected on the structured test image."""
        features = extract_visual_features(self.img)
        self.assertTrue(features.header_banner_detected)
        self.assertGreaterEqual(features.button_candidate_count, 1)

    def test_uniform_image_edge_cases(self):
        """Plain white image should produce zero buttons, low edge density, and high whitespace."""
        plain = Image.new("RGB", (200, 200), color=(255, 255, 255))
        features = extract_visual_features(plain)

        self.assertEqual(features.whitespace_ratio, 1.0)
        self.assertEqual(features.edge_density, 0.0)
        self.assertFalse(features.header_banner_detected)
        self.assertEqual(features.button_candidate_count, 0)
        self.assertFalse(features.qr_candidate_detected)

    def test_shannon_entropy_calculation(self):
        """Uniform array has 0 entropy; random binary array has ~1 bit entropy."""
        flat = np.full((100, 100), 128, dtype=np.uint8)
        self.assertEqual(compute_shannon_entropy(flat), 0.0)

        # 50/50 black and white has 1.0 bit entropy
        half = np.zeros((100, 100), dtype=np.uint8)
        half[:50, :] = 255
        self.assertAlmostEqual(compute_shannon_entropy(half), 1.0, places=2)

    def test_evidence_item_generation(self):
        """Evidence generator translates measurements to explainable items."""
        features = extract_visual_features(self.img)
        evidence = extract_visual_evidence(features)

        self.assertIsInstance(evidence, list)
        self.assertGreater(len(evidence), 0)
        for item in evidence:
            self.assertIsInstance(item, VisualEvidenceItem)
            self.assertIn(item.role, ["visual_observation", "contextual_signal"])
            self.assertIsInstance(item.reason, str)


if __name__ == "__main__":
    unittest.main()
