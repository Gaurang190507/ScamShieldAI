"""Unit tests for dataset schema validation and boundary enforcement."""

import unittest
from src.data.dataset_schema import REQUIRED_COLUMNS
from src.data.dataset_validator import DatasetValidator


def create_valid_sample_fixture() -> dict:
    """Returns an isolated, compliant mock record for unit testing."""
    return {
        "sample_id": "test_samp_001",
        "text": "URGENT: Your bank account will be blocked today. Verify your identity now at https://secure-bank.example.com",
        "language": "en",
        "source_type": "official_advisory",
        "label": "scam",
        "scam_category": "phishing",
        "tactics": ["urgency", "account_suspension", "verification_request", "link_redirection"],
        "evidence_spans": [
            {"tactic": "urgency", "evidence": "URGENT:"},
            {"tactic": "account_suspension", "evidence": "account will be blocked"},
            {"tactic": "verification_request", "evidence": "Verify your identity"},
            {"tactic": "link_redirection", "evidence": "https://secure-bank.example.com"},
        ],
        "requested_action": "click_link",
        "target_asset": "bank_account",
        "urgency_level": "high",
        "impersonated_entity": "bank",
        "has_url": True,
        "urls": ["https://secure-bank.example.com"],
        "has_phone_number": False,
        "has_payment_request": False,
        "source_reference": "ref_cyber_alert_12",
        "collection_date": "2026-10-02",
        "label_confidence": "high",
        "annotator_id": "test_reviewer_1",
        "pattern_group_id": "grp_bank_block_v1",
        "known_unknown_status": "known",
        "notes": "Test fixture for unit validation.",
    }


class TestDatasetValidator(unittest.TestCase):
    def setUp(self):
        self.validator = DatasetValidator()
        self.valid_record = create_valid_sample_fixture()

    def test_valid_record_passes(self):
        errors = self.validator.validate_record(self.valid_record)
        self.assertEqual(errors, [], f"Expected 0 errors, got: {errors}")

    def test_missing_required_column_fails(self):
        record = self.valid_record.copy()
        del record["pattern_group_id"]
        errors = self.validator.validate_record(record)
        self.assertTrue(any("Missing required column" in e for e in errors))

    def test_invalid_label_fails(self):
        record = self.valid_record.copy()
        record["label"] = "fraudulent"  # Not in allowed ('scam', 'non_scam')
        errors = self.validator.validate_record(record)
        self.assertTrue(any("Invalid label 'fraudulent'" in e for e in errors))

    def test_invalid_tactic_not_in_vocabulary_fails(self):
        record = self.valid_record.copy()
        record["tactics"] = ["urgency", "mind_reading_trick"]
        errors = self.validator.validate_record(record)
        self.assertTrue(any("Unknown tactic" in e for e in errors))

    def test_malformed_evidence_span_wrong_structure_fails(self):
        record = self.valid_record.copy()
        record["evidence_spans"] = ["just a string instead of dict"]
        errors = self.validator.validate_record(record)
        self.assertTrue(any("must be a dictionary" in e for e in errors))

    def test_evidence_span_not_in_text_fails(self):
        record = self.valid_record.copy()
        record["evidence_spans"] = [
            {"tactic": "urgency", "evidence": "this phrase is nowhere in the text"}
        ]
        errors = self.validator.validate_record(record)
        self.assertTrue(any("not a verbatim substring" in e for e in errors))

    def test_evidence_span_tactic_mismatch_fails(self):
        record = self.valid_record.copy()
        # "threat" is in controlled vocabulary, but not in record["tactics"]
        record["evidence_spans"] = [
            {"tactic": "threat", "evidence": "account will be blocked"}
        ]
        errors = self.validator.validate_record(record)
        self.assertTrue(any("not listed in 'tactics'" in e for e in errors))

    def test_invalid_boolean_field_fails(self):
        record = self.valid_record.copy()
        record["has_url"] = "True"  # String instead of strict bool
        errors = self.validator.validate_record(record)
        self.assertTrue(any("'has_url' must be a boolean" in e for e in errors))

    def test_invalid_enum_values_fail(self):
        record = self.valid_record.copy()
        record["urgency_level"] = "super_critical"
        record["label_confidence"] = "definite"
        record["known_unknown_status"] = "somewhat_new"
        errors = self.validator.validate_record(record)
        self.assertTrue(any("Invalid urgency_level" in e for e in errors))
        self.assertTrue(any("Invalid label_confidence" in e for e in errors))
        self.assertTrue(any("Invalid known_unknown_status" in e for e in errors))

    def test_duplicate_sample_ids_in_dataset_fails(self):
        rec1 = self.valid_record.copy()
        rec2 = self.valid_record.copy()
        rec1["sample_id"] = "dup_id"
        rec2["sample_id"] = "dup_id"
        result = self.validator.validate_dataset([rec1, rec2])
        self.assertFalse(result.is_valid)
        self.assertTrue(any("Duplicate sample_id 'dup_id'" in e for e in result.errors))


if __name__ == "__main__":
    unittest.main()
