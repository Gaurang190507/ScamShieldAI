"""Unit tests for UCI SMS Spam Collection ingestion and normalization pipeline."""

import unittest
from unittest.mock import patch
import socket

from src.data.ingest_uci_sms import (
    parse_uci_line,
    normalize_uci_record,
    extract_urls,
    extract_phone_numbers,
    has_payment_cue,
)
from src.data.dataset_schema import (
    Label,
    ScamCategory,
    SourceType,
    LabelConfidence,
)
from src.data.dataset_validator import DatasetValidator


class TestIngestUCISMS(unittest.TestCase):
    def setUp(self):
        self.validator = DatasetValidator()

    def test_parse_valid_uci_row(self):
        line = "ham\tHello, what time are we meeting today?"
        orig_lbl, text = parse_uci_line(line, line_num=1)
        self.assertEqual(orig_lbl, "ham")
        self.assertEqual(text, "Hello, what time are we meeting today?")

    def test_ham_to_non_scam_normalization(self):
        rec = normalize_uci_record("ham", "Are you coming home for dinner?", line_num=42)
        self.assertEqual(rec["label"], Label.NON_SCAM.value)
        self.assertEqual(rec["scam_category"], ScamCategory.NONE.value)
        self.assertEqual(rec["label_confidence"], LabelConfidence.HIGH.value)
        self.assertEqual(rec["tactics"], [])
        self.assertEqual(rec["evidence_spans"], [])

    def test_spam_to_scam_normalization(self):
        rec = normalize_uci_record(
            "spam", "WINNER! You won a £1,000 prize. Call 087124006024 now.", line_num=99
        )
        self.assertEqual(rec["label"], Label.SCAM.value)
        self.assertEqual(rec["scam_category"], ScamCategory.UNKNOWN.value)
        self.assertEqual(rec["label_confidence"], LabelConfidence.MEDIUM.value)
        self.assertEqual(rec["tactics"], [])
        self.assertEqual(rec["evidence_spans"], [])

    def test_invalid_original_label_rejection(self):
        line = "phish\tClick here to reset password"
        with self.assertRaises(ValueError) as ctx:
            parse_uci_line(line, line_num=10)
        self.assertIn("unrecognized original label", str(ctx.exception))

    def test_empty_line_and_empty_message_handling(self):
        with self.assertRaises(ValueError) as ctx_empty:
            parse_uci_line("", line_num=1)
        self.assertIn("empty", str(ctx_empty.exception))

        with self.assertRaises(ValueError) as ctx_no_text:
            parse_uci_line("ham\t   ", line_num=2)
        self.assertIn("empty message text", str(ctx_no_text.exception))

        with self.assertRaises(ValueError) as ctx_malformed:
            parse_uci_line("single_field_without_tab", line_num=3)
        self.assertIn("tab-separated", str(ctx_malformed.exception))

    def test_provenance_preservation(self):
        line_num = 1234
        rec = normalize_uci_record("ham", "Meeting confirmed.", line_num=line_num)
        self.assertEqual(rec["sample_id"], f"uci_sms_{line_num:04d}")
        self.assertEqual(rec["source_reference"], f"src_uci_sms_spam_228#L{line_num}")
        self.assertEqual(rec["source_type"], SourceType.PUBLIC_DATASET.value)
        self.assertIn(f"row {line_num}", rec["notes"])

    def test_deterministic_url_extraction(self):
        text = "Visit http://example.com/login and www.bank-alert.co.uk! or www.test.org."
        urls = extract_urls(text)
        self.assertIn("http://example.com/login", urls)
        self.assertIn("www.bank-alert.co.uk", urls)
        self.assertIn("www.test.org", urls)
        # Ensure trailing punctuation was cleanly stripped
        self.assertNotIn("www.bank-alert.co.uk!", urls)

    def test_phone_and_payment_cues(self):
        text = "Win £500! Call 08712345678 now or text 88888. Costs 50p/min."
        self.assertTrue(has_payment_cue(text))
        phones = extract_phone_numbers(text)
        self.assertTrue(len(phones) >= 1)

    def test_schema_validation_of_normalized_records(self):
        ham_rec = normalize_uci_record("ham", "Sounds great, see you at 7pm.", line_num=1)
        spam_rec = normalize_uci_record(
            "spam", "Urgent! Claim your cash prize now at http://win.com", line_num=2
        )

        ham_errors = self.validator.validate_record(ham_rec)
        spam_errors = self.validator.validate_record(spam_rec)

        self.assertEqual(ham_errors, [], f"Ham errors: {ham_errors}")
        self.assertEqual(spam_errors, [], f"Spam errors: {spam_errors}")

    def test_no_network_requests_during_ingestion(self):
        # Guard against accidental network calls
        with patch.object(
            socket, "socket", side_effect=RuntimeError("NETWORK CALL DETECTED!")
        ):
            text_with_links = (
                "Suspicious link: http://malicious-site.example.com/steal-creds "
                "Contact: http://192.168.1.1/phish"
            )
            # Must extract URLs purely in-memory
            urls = extract_urls(text_with_links)
            self.assertEqual(len(urls), 2)
            rec = normalize_uci_record("spam", text_with_links, line_num=500)
            self.assertTrue(rec["has_url"])
            self.assertEqual(len(rec["urls"]), 2)


if __name__ == "__main__":
    unittest.main()
