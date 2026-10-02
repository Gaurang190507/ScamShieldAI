"""Unit tests for leakage-safe pattern group splitting."""

import unittest
import pandas as pd
from src.data.leakage_split import group_leakage_split, verify_no_group_leakage


class TestLeakageSplit(unittest.TestCase):
    def setUp(self):
        # 10 mock records belonging to 4 distinct campaign groups
        self.mock_data = [
            {"sample_id": f"s_{i}", "pattern_group_id": f"grp_{i % 4}", "text": f"msg {i}"}
            for i in range(12)
        ]
        self.df = pd.DataFrame(self.mock_data)

    def test_group_split_prevents_leakage(self):
        train_df, val_df, test_df = group_leakage_split(
            self.df,
            group_col="pattern_group_id",
            test_size=0.25,
            val_size=0.25,
            random_state=42,
        )

        # Ensure no pattern group is shared between partitions
        train_groups = set(train_df["pattern_group_id"].unique())
        val_groups = set(val_df["pattern_group_id"].unique())
        test_groups = set(test_df["pattern_group_id"].unique())

        self.assertEqual(len(train_groups.intersection(val_groups)), 0)
        self.assertEqual(len(train_groups.intersection(test_groups)), 0)
        self.assertEqual(len(val_groups.intersection(test_groups)), 0)

        is_clean, msg = verify_no_group_leakage(train_df, val_df, test_df)
        self.assertTrue(is_clean, msg)

    def test_leakage_verification_detects_overlap(self):
        # Intentionally construct an overlapping partition
        train_df = pd.DataFrame([{"pattern_group_id": "grp_alpha"}])
        val_df = pd.DataFrame([{"pattern_group_id": "grp_beta"}])
        test_df = pd.DataFrame([{"pattern_group_id": "grp_alpha"}])  # Leaked from train!

        is_clean, msg = verify_no_group_leakage(train_df, val_df, test_df)
        self.assertFalse(is_clean)
        self.assertIn("LEAKAGE DETECTED", msg)


if __name__ == "__main__":
    unittest.main()
