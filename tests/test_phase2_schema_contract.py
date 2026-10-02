"""Contract and integrity tests for Phase 2 preprocessed output schema.

Tests:
1. Canonical fields preserved
2. Raw text preserved
3. Sample IDs preserved
4. Record count preserved
5. Canonical labels and annotations preserved
6. Preprocessing extension exists with valid structure
7. Deterministic preprocessing reproducibility
8. Valid JSONL syntax and data types
9. No conflicting duplicate canonical fields
10. Representative entity extraction accuracy on known examples
"""

import json
import math
import unittest
from pathlib import Path

from src.data.dataset_schema import REQUIRED_COLUMNS, Label, ScamCategory
from src.preprocessing.preprocess_message import preprocess_record


class TestPhase2SchemaContract(unittest.TestCase):
    """Schema contract verification for data/processed/preprocessed/uci_sms_spam.jsonl."""

    @classmethod
    def setUpClass(cls):
        cls.root_dir = Path(__file__).resolve().parents[1]
        cls.input_path = cls.root_dir / "data" / "processed" / "uci_sms_spam.jsonl"
        cls.output_path = cls.root_dir / "data" / "processed" / "preprocessed" / "uci_sms_spam.jsonl"

        if not cls.input_path.is_file():
            raise FileNotFoundError(f"Input file missing: {cls.input_path}")
        if not cls.output_path.is_file():
            raise FileNotFoundError(f"Output file missing: {cls.output_path}")

        with open(cls.input_path, "r", encoding="utf-8") as f:
            cls.input_records = [json.loads(line) for line in f]

        with open(cls.output_path, "r", encoding="utf-8") as f:
            cls.output_records = [json.loads(line) for line in f]

    def test_01_canonical_fields_preserved(self):
        """Test 1: Every preprocessed record contains all 23 canonical schema fields."""
        for idx, rec in enumerate(self.output_records):
            for col in REQUIRED_COLUMNS:
                self.assertIn(
                    col,
                    rec,
                    f"Record at index {idx} (sample_id: {rec.get('sample_id')}) missing canonical field '{col}'",
                )

    def test_02_raw_text_preserved(self):
        """Test 2: The output 'text' exactly matches the input 'text' byte-for-byte."""
        for in_rec, out_rec in zip(self.input_records, self.output_records):
            self.assertEqual(
                out_rec["text"],
                in_rec["text"],
                f"Mismatch in raw text for sample_id {in_rec['sample_id']}",
            )

    def test_03_sample_ids_preserved(self):
        """Test 3: Every input sample ID appears exactly once in the output in identical order."""
        in_ids = [r["sample_id"] for r in self.input_records]
        out_ids = [r["sample_id"] for r in self.output_records]

        self.assertEqual(len(out_ids), len(set(out_ids)), "Duplicate sample_ids detected in output")
        self.assertEqual(in_ids, out_ids, "Sample IDs order or content differs from input")

    def test_04_record_count_preserved(self):
        """Test 4: Input and output contain the exact same number of records."""
        self.assertEqual(
            len(self.input_records),
            len(self.output_records),
            f"Record count changed: input={len(self.input_records)}, output={len(self.output_records)}",
        )
        self.assertEqual(len(self.output_records), 5574)

    def test_05_canonical_labels_preserved(self):
        """Test 5: Canonical label and annotation fields are completely unmodified."""
        annotation_fields = [
            "label",
            "scam_category",
            "tactics",
            "evidence_spans",
            "requested_action",
            "target_asset",
            "urgency_level",
            "impersonated_entity",
            "source_type",
            "label_confidence",
            "known_unknown_status",
            "pattern_group_id",
            "source_reference",
        ]
        for in_rec, out_rec in zip(self.input_records, self.output_records):
            for field_name in annotation_fields:
                self.assertEqual(
                    out_rec[field_name],
                    in_rec[field_name],
                    f"Field '{field_name}' was altered for sample_id {in_rec['sample_id']}",
                )

    def test_06_preprocessing_extension_exists(self):
        """Test 6: Preprocessed records contain valid normalized_text, analysis_text, features, and entities."""
        required_feature_keys = [
            "character_count",
            "word_count",
            "digit_count",
            "uppercase_count",
            "uppercase_ratio",
            "digit_ratio",
            "exclamation_count",
            "question_mark_count",
            "special_character_count",
            "line_count",
            "emoji_count",
            "has_url",
            "url_count",
            "has_phone_number",
            "phone_count",
            "has_email",
            "email_count",
            "has_currency",
            "currency_count",
            "amount_values",
            "otp_related",
            "has_repeated_punctuation",
            "max_consecutive_punctuation",
            "repeated_punctuation_count",
            "has_suspicious_unicode",
        ]
        required_entity_keys = ["urls", "phone_numbers", "emails", "currency_mentions"]

        for idx, rec in enumerate(self.output_records):
            self.assertIn("normalized_text", rec)
            self.assertIsInstance(rec["normalized_text"], str)

            self.assertIn("analysis_text", rec)
            self.assertIsInstance(rec["analysis_text"], str)

            self.assertIn("features", rec)
            self.assertIsInstance(rec["features"], dict)
            for k in required_feature_keys:
                self.assertIn(k, rec["features"])

            self.assertIn("entities", rec)
            self.assertIsInstance(rec["entities"], dict)
            for ek in required_entity_keys:
                self.assertIn(ek, rec["entities"])
                self.assertIsInstance(rec["entities"][ek], list)

    def test_07_deterministic_preprocessing(self):
        """Test 7: Running preprocessing twice on the same record produces identical output."""
        sample = self.input_records[12]  # URL & phone sample
        prep_1 = preprocess_record(sample)
        prep_2 = preprocess_record(sample)
        self.assertEqual(prep_1, prep_2)

    def test_08_valid_jsonl(self):
        """Test 8: Every line in output file is valid JSON with valid non-NaN/Inf numerical values."""
        with open(self.output_path, "r", encoding="utf-8") as f:
            for line_idx, line in enumerate(f):
                line_str = line.strip()
                self.assertTrue(line_str, f"Empty line at line {line_idx + 1}")
                parsed = json.loads(line_str)
                # Check numerical values in features for NaN / Infinity
                feats = parsed.get("features", {})
                for k, v in feats.items():
                    if isinstance(v, float):
                        self.assertFalse(
                            math.isnan(v) or math.isinf(v),
                            f"Invalid float ({v}) for feature '{k}' at line {line_idx + 1}",
                        )

    def test_09_no_conflicting_duplicate_fields(self):
        """Test 9: Preprocessing features do NOT duplicate or conflict with canonical annotations."""
        forbidden_feature_keys = {
            "label",
            "scam_category",
            "tactics",
            "evidence_spans",
            "source_type",
            "language",
            "urgency_level",
            "impersonated_entity",
            "requested_action",
            "target_asset",
            "label_confidence",
            "known_unknown_status",
        }
        for rec in self.output_records:
            features = rec.get("features", {})
            for forbidden in forbidden_feature_keys:
                self.assertNotIn(
                    forbidden,
                    features,
                    f"Label or metadata leakage detected in features: '{forbidden}'",
                )

    def test_10_representative_entities(self):
        """Test 10: Entity extraction verifies known representative examples from the dataset."""
        # Record 13 (uci_sms_0013) has URL www.dbuk.net and shortcode 81010
        rec_13 = self.output_records[12]
        self.assertEqual(rec_13["sample_id"], "uci_sms_0013")
        self.assertTrue(rec_13["features"]["has_url"])
        self.assertIn("www.dbuk.net", rec_13["entities"]["urls"])
        self.assertTrue(rec_13["features"]["has_phone_number"])
        self.assertIn("81010", rec_13["entities"]["phone_numbers"])

        # Record 6 (uci_sms_0006) has currency mention £1.50
        rec_6 = self.output_records[5]
        self.assertEqual(rec_6["sample_id"], "uci_sms_0006")
        self.assertTrue(rec_6["features"]["has_currency"])
        self.assertIn("£1.50", rec_6["entities"]["currency_mentions"])
        self.assertIn(1.5, rec_6["features"]["amount_values"])

        # Record 1 (uci_sms_0001) has no extracted entities
        rec_1 = self.output_records[0]
        self.assertEqual(rec_1["sample_id"], "uci_sms_0001")
        self.assertFalse(rec_1["features"]["has_url"])
        self.assertFalse(rec_1["features"]["has_phone_number"])
        self.assertFalse(rec_1["features"]["has_email"])
        self.assertFalse(rec_1["features"]["has_currency"])
        self.assertEqual(rec_1["entities"]["urls"], [])
        self.assertEqual(rec_1["entities"]["phone_numbers"], [])
        self.assertEqual(rec_1["entities"]["emails"], [])
        self.assertEqual(rec_1["entities"]["currency_mentions"], [])


if __name__ == "__main__":
    unittest.main()
