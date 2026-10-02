"""Unit tests for dataset loader and serializer."""

import json
import tempfile
import unittest
from pathlib import Path
import numpy as np
import pandas as pd

from src.data.data_loader import load_dataset, save_dataset, DatasetValidationError
from tests.test_dataset_validator import create_valid_sample_fixture


class TestDataLoader(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.dir_path = Path(self.temp_dir.name)
        self.fixture = create_valid_sample_fixture()

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_jsonl_save_and_load_roundtrip(self):
        df_in = pd.DataFrame([self.fixture])
        jsonl_path = self.dir_path / "test_samples.jsonl"

        save_dataset(df_in, jsonl_path, format="jsonl", validate=True)
        self.assertTrue(jsonl_path.exists())

        df_out = load_dataset(jsonl_path, validate=True)
        self.assertEqual(len(df_out), 1)
        self.assertEqual(df_out.iloc[0]["sample_id"], "test_samp_001")
        self.assertIsInstance(df_out.iloc[0]["tactics"], list)
        self.assertIsInstance(df_out.iloc[0]["evidence_spans"], list)
        self.assertTrue(df_out.iloc[0]["has_url"])

    def test_csv_save_and_load_roundtrip(self):
        df_in = pd.DataFrame([self.fixture])
        csv_path = self.dir_path / "test_samples.csv"

        save_dataset(df_in, csv_path, format="csv", validate=True)
        self.assertTrue(csv_path.exists())

        df_out = load_dataset(csv_path, validate=True)
        self.assertEqual(len(df_out), 1)
        self.assertEqual(df_out.iloc[0]["sample_id"], "test_samp_001")
        # Ensure structured fields were unpacked from CSV JSON strings
        self.assertIsInstance(df_out.iloc[0]["tactics"], list)
        self.assertTrue(df_out.iloc[0]["has_url"])
        self.assertIn(type(df_out.iloc[0]["has_url"]), (bool, np.bool_))

    def test_load_invalid_dataset_raises_validation_error(self):
        bad_fixture = self.fixture.copy()
        bad_fixture["label"] = "not_a_valid_label"
        bad_jsonl = self.dir_path / "bad.jsonl"

        with open(bad_jsonl, "w", encoding="utf-8") as f:
            f.write(json.dumps(bad_fixture) + "\n")

        with self.assertRaises(DatasetValidationError):
            load_dataset(bad_jsonl, validate=True)


if __name__ == "__main__":
    unittest.main()
