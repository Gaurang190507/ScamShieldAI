"""Unit tests for exact and normalized duplicate detection."""

import unittest
from src.data.duplicate_detector import detect_duplicates, normalize_text_for_dedup
from tests.test_dataset_validator import create_valid_sample_fixture


class TestDuplicateDetector(unittest.TestCase):
    def test_text_normalization(self):
        raw = "  URGENT!  Your account... will be blocked??  "
        expected = "urgent your account will be blocked"
        self.assertEqual(normalize_text_for_dedup(raw), expected)

    def test_exact_duplicates_detection(self):
        rec1 = create_valid_sample_fixture()
        rec1["sample_id"] = "s1"

        rec2 = create_valid_sample_fixture()
        rec2["sample_id"] = "s2"

        report = detect_duplicates([rec1, rec2])
        self.assertEqual(report.total_exact_duplicates, 1)
        self.assertEqual(len(report.exact_duplicates), 1)
        self.assertIn("s1", list(report.exact_duplicates.values())[0])
        self.assertIn("s2", list(report.exact_duplicates.values())[0])

    def test_normalized_duplicates_detection(self):
        rec1 = create_valid_sample_fixture()
        rec1["sample_id"] = "s1"
        rec1["text"] = "Verify your account immediately!"

        rec2 = create_valid_sample_fixture()
        rec2["sample_id"] = "s2"
        rec2["text"] = "  verify   your account immediately.  "

        report = detect_duplicates([rec1, rec2])
        self.assertEqual(report.total_exact_duplicates, 0)
        self.assertEqual(report.total_normalized_duplicates, 1)

    def test_no_duplicates_in_distinct_samples(self):
        rec1 = create_valid_sample_fixture()
        rec1["sample_id"] = "s1"
        rec1["text"] = "Electricity bill is overdue."

        rec2 = create_valid_sample_fixture()
        rec2["sample_id"] = "s2"
        rec2["text"] = "Your flight has been rescheduled."

        report = detect_duplicates([rec1, rec2])
        self.assertEqual(report.total_exact_duplicates, 0)
        self.assertEqual(report.total_normalized_duplicates, 0)


if __name__ == "__main__":
    unittest.main()
