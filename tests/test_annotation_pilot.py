"""Unit tests for the Human Annotation Pilot infrastructure and guidelines."""

import json
from pathlib import Path
import unittest

from src.data.dataset_schema import (
    Label,
    ScamCategory,
    SourceType,
    RequestedAction,
    TargetAsset,
    UrgencyLevel,
    ImpersonatedEntity,
    LabelConfidence,
    KnownUnknownStatus,
)
from src.data.dataset_validator import DatasetValidator
from src.data.data_loader import load_dataset


def create_mock_pilot_sample() -> dict:
    """Returns an isolated, compliant mock pilot record."""
    return {
        "sample_id": "pilot_samp_001",
        "text": "URGENT! You have won £1,000 cash. Call 09061701461 to claim now.",
        "language": "en",
        "source_type": SourceType.PUBLIC_DATASET.value,
        "label": Label.SCAM.value,
        "scam_category": ScamCategory.PHISHING.value,
        "tactics": ["urgency", "reward_claim"],
        "evidence_spans": [
            {"tactic": "urgency", "evidence": "URGENT!"},
            {"tactic": "reward_claim", "evidence": "won £1,000 cash"},
        ],
        "requested_action": RequestedAction.CALL_PHONE_NUMBER.value,
        "target_asset": TargetAsset.MONEY.value,
        "urgency_level": UrgencyLevel.HIGH.value,
        "impersonated_entity": ImpersonatedEntity.NONE.value,
        "has_url": False,
        "urls": [],
        "has_phone_number": True,
        "has_payment_request": False,
        "source_reference": "src_uci_sms_spam_228#L9",
        "collection_date": "2026-10-02",
        "label_confidence": LabelConfidence.HIGH.value,
        "annotator_id": "annotator_001",
        "pattern_group_id": "unknown",  # Documented unknown pattern group convention
        "known_unknown_status": KnownUnknownStatus.KNOWN.value,
        "notes": "Verified pilot test fixture.",
    }


class TestAnnotationPilot(unittest.TestCase):
    def setUp(self):
        self.validator = DatasetValidator()
        self.sample = create_mock_pilot_sample()

    def test_1_valid_manually_annotated_record(self):
        errors = self.validator.validate_record(self.sample)
        self.assertEqual(errors, [], f"Expected 0 errors, got: {errors}")

    def test_2_invalid_tactic_rejected(self):
        rec = dict(self.sample)
        rec["tactics"] = ["urgency", "telepathic_manipulation"]
        errors = self.validator.validate_record(rec)
        self.assertTrue(any("Unknown tactic" in e for e in errors))

    def test_3_invalid_evidence_span_rejected(self):
        rec = dict(self.sample)
        rec["evidence_spans"] = [
            {"tactic": "urgency", "evidence": "this phrase is not in the message text"}
        ]
        errors = self.validator.validate_record(rec)
        self.assertTrue(any("not a verbatim substring" in e for e in errors))

    def test_4_evidence_tactic_missing_from_tactics_rejected(self):
        rec = dict(self.sample)
        # "threat" is in controlled vocabulary, but was not included in rec["tactics"]
        rec["evidence_spans"] = [
            {"tactic": "threat", "evidence": "URGENT!"}
        ]
        errors = self.validator.validate_record(rec)
        self.assertTrue(any("not listed in 'tactics'" in e for e in errors))

    def test_5_invalid_confidence_rejected(self):
        rec = dict(self.sample)
        rec["label_confidence"] = "100_percent_sure"
        errors = self.validator.validate_record(rec)
        self.assertTrue(any("Invalid label_confidence" in e for e in errors))

    def test_6_invalid_pattern_group_value(self):
        rec = dict(self.sample)
        rec["pattern_group_id"] = ""  # Empty string is invalid
        errors = self.validator.validate_record(rec)
        self.assertTrue(any("'pattern_group_id' is required" in e for e in errors))

    def test_7_ambiguous_record_with_low_confidence(self):
        rec = dict(self.sample)
        rec["text"] = "Got meh... When?"
        rec["label"] = Label.NON_SCAM.value
        rec["scam_category"] = ScamCategory.NONE.value
        rec["tactics"] = []
        rec["evidence_spans"] = []
        rec["label_confidence"] = LabelConfidence.LOW.value
        rec["known_unknown_status"] = KnownUnknownStatus.UNKNOWN.value
        rec["notes"] = "Ambiguous case: colloquial snippet missing conversational context."

        errors = self.validator.validate_record(rec)
        self.assertEqual(errors, [])

    def test_8_duplicate_sample_id_rejected(self):
        rec1 = dict(self.sample)
        rec2 = dict(self.sample)
        result = self.validator.validate_dataset([rec1, rec2])
        self.assertFalse(result.is_valid)
        self.assertTrue(any("Duplicate sample_id" in e for e in result.errors))

    def test_9_missing_source_reference_rejected(self):
        rec = dict(self.sample)
        del rec["source_reference"]
        errors = self.validator.validate_record(rec)
        self.assertTrue(any("Missing required column" in e for e in errors))

    def test_10_successful_validator_execution_on_pilot_file(self):
        root = Path(__file__).resolve().parents[1]
        pilot_path = root / "data" / "evaluation" / "annotation_pilot" / "pilot_dataset.jsonl"
        self.assertTrue(pilot_path.is_file(), f"Pilot dataset file missing at: {pilot_path}")

        df = load_dataset(pilot_path, validate=True)
        self.assertEqual(len(df), 60)
        self.assertTrue(all(df["pattern_group_id"] == "unknown"))
        self.assertTrue(all(df["annotator_id"] == "annotator_001"))


if __name__ == "__main__":
    unittest.main()
