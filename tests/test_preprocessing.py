"""Unit tests for ScamShield AI deterministic preprocessing and feature extraction layer.

Tests:
- Normalization (whitespace, tabs, Unicode NFKC, empty strings, punctuation & URL preservation)
- URL extraction (http, https, www, trailing punctuation cleanup, no URLs)
- Phone extraction (international, Indian mobile, shortcodes, exclusion of amounts/units/dates)
- Email extraction (valid emails, text without emails)
- Currency extraction (₹500, Rs 500, INR 500, $100, 500 rupees, amount parsing)
- OTP detection (OTP, verification code, authentication code, ordinary numbers)
- Formatting & Repetition (exclamation streaks, question marks, repetition counts)
- Unicode analysis (normal text vs zero-width chars, math alphanumeric, mixed-script homoglyphs)
- Evidence preservation (processed.text == original_text byte-for-byte)
- Offline safety (zero socket connections, zero network requests)
"""

import unittest
from unittest.mock import patch
import socket
import urllib.request

from src.preprocessing.schemas import (
    PreprocessedMessage,
    ExtractedEntities,
    TextFeatures,
)
from src.preprocessing.normalize import (
    normalize_unicode,
    normalize_whitespace,
    build_normalized_text,
    build_analysis_text,
    clean_text,
)
from src.preprocessing.extract_entities import (
    extract_urls,
    extract_emails,
    extract_phone_numbers,
    extract_currencies,
    extract_all_entities,
)
from src.preprocessing.extract_features import (
    extract_text_features,
    is_otp_related,
    count_emojis,
    analyze_punctuation_repetition,
    has_suspicious_unicode,
)
from src.preprocessing.preprocess_message import (
    preprocess_message,
    preprocess_record,
)


class TestNormalization(unittest.TestCase):
    """Tests for deterministic text normalization."""

    def test_whitespace_normalization_multiple_spaces(self):
        raw = "Hello     user,   please check    your  account."
        expected = "Hello user, please check your account."
        self.assertEqual(normalize_whitespace(raw), expected)

    def test_whitespace_normalization_tabs_and_newlines(self):
        raw = "Line 1\t\tdetails.\r\n\r\n\r\nLine 2\tinformation."
        normalized = normalize_whitespace(raw)
        self.assertIn("Line 1 details.", normalized)
        self.assertIn("Line 2 information.", normalized)
        self.assertNotIn("\t", normalized)
        self.assertNotIn("\r", normalized)

    def test_unicode_normalization_nfkc(self):
        # Fullwidth Latin letters and ligature 'fi'
        raw = "Ｈｅｌｌｏ ｗｏｒｌｄ ﬁle"
        normalized = normalize_unicode(raw)
        self.assertEqual(normalized, "Hello world file")

    def test_empty_and_none_input(self):
        self.assertEqual(normalize_unicode(""), "")
        self.assertEqual(normalize_whitespace(""), "")
        self.assertEqual(build_normalized_text(""), "")
        self.assertEqual(build_analysis_text(""), "")
        self.assertEqual(clean_text(""), "")

    def test_punctuation_preservation(self):
        raw = "URGENT!!! Is this your card number? Call now (today)..."
        norm = build_normalized_text(raw)
        self.assertEqual(norm, raw)
        self.assertIn("!!!", norm)
        self.assertIn("?", norm)
        self.assertIn("...", norm)

    def test_url_preservation_in_normalization(self):
        raw = "Visit https://bank.example.com/verify?id=123 immediately."
        norm = build_normalized_text(raw)
        self.assertEqual(norm, raw)
        self.assertIn("https://bank.example.com/verify?id=123", norm)

    def test_analysis_text_lowercase_preserving_tokens(self):
        raw = "URGENT: Pay ₹500 via https://pay.example.com now!"
        analysis = build_analysis_text(raw)
        self.assertEqual(analysis, "urgent: pay ₹500 via https://pay.example.com now!")
        self.assertIn("₹500", analysis)
        self.assertIn("https://pay.example.com", analysis)


class TestEntityExtraction(unittest.TestCase):
    """Tests for deterministic extraction of URLs, emails, phones, and currencies."""

    def test_url_extraction_http_https_www(self):
        text = "Visit https://secure-bank.com/login and http://update.org or www.verify-id.net for help."
        urls = extract_urls(text)
        self.assertEqual(len(urls), 3)
        self.assertIn("https://secure-bank.com/login", urls)
        self.assertIn("http://update.org", urls)
        self.assertIn("www.verify-id.net", urls)

    def test_url_extraction_trailing_punctuation_cleanup(self):
        text = "Check this link: https://portal.example.com/auth, and then http://test.com."
        urls = extract_urls(text)
        self.assertEqual(urls, ["https://portal.example.com/auth", "http://test.com"])

    def test_url_extraction_no_urls(self):
        text = "Just a normal message without any web links."
        self.assertEqual(extract_urls(text), [])

    def test_email_extraction_valid(self):
        text = "Contact support at helpdesk@bank-secure.co.in or fraud-desk@alerts.com."
        emails = extract_emails(text)
        self.assertEqual(len(emails), 2)
        self.assertIn("helpdesk@bank-secure.co.in", emails)
        self.assertIn("fraud-desk@alerts.com", emails)

    def test_email_extraction_no_emails(self):
        text = "Please reach out to our service centre in person."
        self.assertEqual(extract_emails(text), [])

    def test_currency_extraction_various_formats(self):
        text = "Pay ₹500 today or Rs 500 later. Amount is INR 500, but fee is $100 or 500 rupees."
        mentions, values = extract_currencies(text)
        self.assertGreaterEqual(len(mentions), 5)
        self.assertIn(500.0, values)
        self.assertIn(100.0, values)

    def test_currency_extraction_with_multipliers(self):
        text = "You won Rs 5 lakh in the contest and $1.5 million in jackpot!"
        mentions, values = extract_currencies(text)
        self.assertEqual(len(mentions), 2)
        self.assertIn(500000.0, values)
        self.assertIn(1500000.0, values)

    def test_phone_number_extraction_valid_formats(self):
        text = "Call us at +91 9876543210 or 9876543210 or 0800 123 4567 or reply to 56767."
        phones = extract_phone_numbers(text)
        self.assertGreaterEqual(len(phones), 3)

    def test_phone_number_extraction_filters_amounts_and_dates(self):
        # Ordinary amounts ($1,000, ₹500, 2004 points, 24 hours, date 2026-10-02) must NOT be extracted as phones
        text = "Your bill of ₹500 is due on 2026-10-02. You have 2004 points for $1,000 credit in 24 hours."
        phones = extract_phone_numbers(text)
        self.assertEqual(phones, [])

    def test_extract_all_entities(self):
        text = "Send ₹250 to support@pay.com or visit https://pay.com or call 9876543210."
        entities = extract_all_entities(text)
        self.assertIsInstance(entities, ExtractedEntities)
        self.assertEqual(entities.urls, ["https://pay.com"])
        self.assertEqual(entities.emails, ["support@pay.com"])
        self.assertEqual(len(entities.phone_numbers), 1)
        self.assertIn("₹250", entities.currency_mentions)


class TestFeatureExtraction(unittest.TestCase):
    """Tests for deterministic feature extraction and behavioral indicators."""

    def test_otp_detection(self):
        self.assertTrue(is_otp_related("Your OTP is 123456."))
        self.assertTrue(is_otp_related("Your one-time password is valid for 10 minutes."))
        self.assertTrue(is_otp_related("Use verification code 882910 to confirm login."))
        self.assertTrue(is_otp_related("Enter the authentication code sent to your phone."))
        self.assertFalse(is_otp_related("Meeting scheduled at 123456 Oak Avenue."))

    def test_formatting_and_repeated_punctuation(self):
        text1 = "URGENT!!!"
        has_rep, max_streak, count = analyze_punctuation_repetition(text1)
        self.assertTrue(has_rep)
        self.assertEqual(max_streak, 3)
        self.assertEqual(count, 1)

        text2 = "CLICK NOW!!!!!! Claim prize $$$$$"
        has_rep2, max_streak2, count2 = analyze_punctuation_repetition(text2)
        self.assertTrue(has_rep2)
        self.assertEqual(max_streak2, 6)
        self.assertEqual(count2, 2)

        text3 = "Normal sentence with regular punctuation."
        has_rep3, max_streak3, count3 = analyze_punctuation_repetition(text3)
        self.assertFalse(has_rep3)
        self.assertEqual(max_streak3, 0)
        self.assertEqual(count3, 0)

    def test_emoji_counting(self):
        text = "Hello! ⚠️ Warning: Action required 🚨💰"
        self.assertEqual(count_emojis(text), 3)

    def test_unicode_anomaly_detection(self):
        # Clean text
        self.assertFalse(has_suspicious_unicode("Standard English message with normal text."))

        # Zero-width space
        self.assertTrue(has_suspicious_unicode("Hidden\u200bSpace"))

        # Right-to-left override
        self.assertTrue(has_suspicious_unicode("Account\u202eUpdate"))

        # Mathematical alphanumeric block (e.g., 𝑼𝑹𝑮𝑬𝑵𝑻)
        math_text = "\U0001D414\U0001D411\U0001D406"
        self.assertTrue(has_suspicious_unicode(math_text))

        # Mixed-script token: Latin "paypa" + Cyrillic "а" (\u0430)
        mixed_text = "Login to payp\u0430l.com immediately."
        self.assertTrue(has_suspicious_unicode(mixed_text))

    def test_extract_text_features_comprehensive(self):
        text = "URGENT! Pay ₹1,500 at https://pay.com now! Verification code required."
        features = extract_text_features(text)
        self.assertIsInstance(features, TextFeatures)
        self.assertTrue(features.has_url)
        self.assertEqual(features.url_count, 1)
        self.assertTrue(features.has_currency)
        self.assertIn(1500.0, features.amount_values)
        self.assertTrue(features.otp_related)
        self.assertGreater(features.uppercase_count, 5)
        self.assertGreater(features.exclamation_count, 1)
        self.assertGreater(features.word_count, 5)


class TestMessagePreprocessingPipeline(unittest.TestCase):
    """Tests for message preprocessing and evidence preservation."""

    def test_evidence_preservation_raw_text_exact_match(self):
        original = "  ALERT!!! Your SBI Account #12345 is LOCKED. Visit: http://sbi-fake.com  "
        preprocessed = preprocess_message(original, sample_id="test_001")
        # Raw text must NOT be stripped or altered — strict byte-for-byte evidence match
        self.assertEqual(preprocessed.text, original)
        self.assertEqual(preprocessed.sample_id, "test_001")

        # Normalized text should have normalized whitespace
        self.assertNotEqual(preprocessed.normalized_text, original)
        self.assertEqual(
            preprocessed.normalized_text,
            "ALERT!!! Your SBI Account #12345 is LOCKED. Visit: http://sbi-fake.com",
        )

        # Analysis text should be lowercase
        self.assertEqual(
            preprocessed.analysis_text,
            "alert!!! your sbi account #12345 is locked. visit: http://sbi-fake.com",
        )

    def test_preprocess_record_preserves_existing_keys(self):
        record = {
            "sample_id": "test_002",
            "text": "Your package is waiting for delivery.",
            "label": "non_scam",
            "tactics": [],
            "source_type": "public_dataset",
        }
        augmented = preprocess_record(record)
        self.assertEqual(augmented["text"], record["text"])
        self.assertEqual(augmented["label"], "non_scam")
        self.assertEqual(augmented["source_type"], "public_dataset")
        self.assertIn("normalized_text", augmented)
        self.assertIn("analysis_text", augmented)
        self.assertIn("features", augmented)
        self.assertIn("entities", augmented)


class TestOfflineSafety(unittest.TestCase):
    """Strict verification that preprocessing initiates zero network connections."""

    @patch("socket.socket")
    @patch("urllib.request.urlopen")
    def test_zero_network_calls_during_preprocessing(self, mock_urlopen, mock_socket):
        sample = {
            "sample_id": "test_net_001",
            "text": "Please verify https://fraud-site.example.com by emailing test@phish.net or calling +91 9999999999.",
        }
        # Execute preprocessing
        result = preprocess_message(sample)

        # Assert no socket creation or network connections occurred
        mock_socket.assert_not_called()
        mock_urlopen.assert_not_called()
        self.assertEqual(len(result.entities.urls), 1)
        self.assertEqual(result.entities.urls[0], "https://fraud-site.example.com")


if __name__ == "__main__":
    unittest.main()
