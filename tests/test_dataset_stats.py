"""Unit tests for dataset distribution and profiling statistics."""

import unittest
from src.data.dataset_stats import generate_dataset_statistics, format_statistics_report
from tests.test_dataset_validator import create_valid_sample_fixture


class TestDatasetStats(unittest.TestCase):
    def test_statistics_aggregation(self):
        rec1 = create_valid_sample_fixture()
        rec1["sample_id"] = "s1"
        rec1["tactics"] = ["urgency", "impersonation"]

        rec2 = create_valid_sample_fixture()
        rec2["sample_id"] = "s2"
        rec2["label"] = "non_scam"
        rec2["tactics"] = ["urgency"]  # Non-scam with urgent language

        stats = generate_dataset_statistics([rec1, rec2])
        self.assertEqual(stats["total_samples"], 2)
        self.assertEqual(stats["label_distribution"]["scam"], 1)
        self.assertEqual(stats["label_distribution"]["non_scam"], 1)
        self.assertEqual(stats["tactic_frequencies"]["urgency"], 2)
        self.assertEqual(stats["tactic_frequencies"]["impersonation"], 1)

        report_text = format_statistics_report(stats)
        self.assertIn("Total Samples: 2", report_text)
        self.assertIn("urgency: 2", report_text)


if __name__ == "__main__":
    unittest.main()
