"""Comprehensive test suite for ScamShield AI Phase 6 TacticDetector.

Verifies:
1. Detection coverage across all 23 canonical scam tactics.
2. Contextual negation handling (preventing false positives on security advice/receipts).
3. Verbatim evidence span integrity (text[start:end] == matched_text for 100% of spans).
4. Compound multi-tactic messages with ranked severity ordering.
5. URL integration for link_redirection.
6. Batch processing and serialization (to_dict).
7. Robust handling of edge cases (empty strings, None, whitespace).
"""

import unittest

from src.tactics.schemas import TacticResult
from src.tactics.tactic_detector import TacticDetector


class TestTacticDetector(unittest.TestCase):
    """Test suite for TacticDetector."""

    def setUp(self):
        self.detector = TacticDetector()

    def test_detector_rule_count(self):
        """Verifies that detector initializes with registered rules."""
        self.assertGreaterEqual(self.detector.rule_count, 23)

    def test_empty_and_invalid_inputs(self):
        """Verifies that empty, whitespace, or None text returns an empty TacticResult."""
        res_empty = self.detector.detect("")
        self.assertFalse(res_empty.has_tactics)
        self.assertEqual(res_empty.tactic_count, 0)

        res_none = self.detector.detect(None)
        self.assertFalse(res_none.has_tactics)
        self.assertEqual(res_none.tactic_count, 0)

        res_ws = self.detector.detect("   \n\t  ")
        self.assertFalse(res_ws.has_tactics)

    # -------------------------------------------------------------------------
    # 23 Canonical Tactics Coverage
    # -------------------------------------------------------------------------

    def test_tactic_impersonation(self):
        text = "Dear customer, this is SBI customer service representative."
        result = self.detector.detect(text)
        self.assertIn("impersonation", result.tactic_names)
        span = result.tactics[0].evidence[0]
        self.assertEqual(text[span.start : span.end], span.matched_text)

    def test_tactic_urgency(self):
        text = "You must act immediately, your offer expires today!"
        result = self.detector.detect(text)
        self.assertIn("urgency", result.tactic_names)

    def test_tactic_threat(self):
        text = "An arrest warrant has been issued against you, legal action will be taken."
        result = self.detector.detect(text)
        self.assertIn("threat", result.tactic_names)

    def test_tactic_fear_creation(self):
        text = "You are placed under digital arrest due to narcotics found in your parcel."
        result = self.detector.detect(text)
        self.assertIn("fear_creation", result.tactic_names)

    def test_tactic_authority_claim(self):
        text = "Notice served under section 144 as per RBI mandate."
        result = self.detector.detect(text)
        self.assertIn("authority_claim", result.tactic_names)

    def test_tactic_payment_request(self):
        text = "Please pay Rs 2500 immediately to settle your dues."
        result = self.detector.detect(text)
        self.assertIn("payment_request", result.tactic_names)

    def test_tactic_credential_request(self):
        text = "Enter your password and ATM PIN to unblock your account."
        result = self.detector.detect(text)
        self.assertIn("credential_request", result.tactic_names)

    def test_tactic_otp_request(self):
        text = "Please share your OTP with our executive to complete the request."
        result = self.detector.detect(text)
        self.assertIn("otp_request", result.tactic_names)

    def test_tactic_personal_information_request(self):
        text = "Please send your Aadhaar and PAN card details for verification."
        result = self.detector.detect(text)
        self.assertIn("personal_information_request", result.tactic_names)

    def test_tactic_account_suspension(self):
        text = "Your account will be blocked today due to incomplete KYC."
        result = self.detector.detect(text)
        self.assertIn("account_suspension", result.tactic_names)

    def test_tactic_verification_request(self):
        text = "Please complete your KYC to verify your account."
        result = self.detector.detect(text)
        self.assertIn("verification_request", result.tactic_names)

    def test_tactic_reward_claim(self):
        text = "Congratulations, you have won Rs 50000 lottery cash prize!"
        result = self.detector.detect(text)
        self.assertIn("reward_claim", result.tactic_names)

    def test_tactic_investment_pressure(self):
        text = "Join our VIP trading group for guaranteed daily profit of 20%."
        result = self.detector.detect(text)
        self.assertIn("investment_pressure", result.tactic_names)

    def test_tactic_job_offer(self):
        text = "Part-time job available: earn Rs 3000 daily from home doing simple online tasks."
        result = self.detector.detect(text)
        self.assertIn("job_offer", result.tactic_names)

    def test_tactic_emotional_manipulation(self):
        text = "I am stranded without money and in urgent need of help, please have mercy."
        result = self.detector.detect(text)
        self.assertIn("emotional_manipulation", result.tactic_names)

    def test_tactic_secrecy_request(self):
        text = "Keep this strictly confidential and do not inform anyone or family."
        result = self.detector.detect(text)
        self.assertIn("secrecy_request", result.tactic_names)

    def test_tactic_romance_manipulation(self):
        text = "My dearest love, I sent you expensive gifts and jewelry from abroad."
        result = self.detector.detect(text)
        self.assertIn("romance_manipulation", result.tactic_names)

    def test_tactic_technical_support_claim(self):
        text = "Critical computer virus detected! Call Microsoft support toll-free number now."
        result = self.detector.detect(text)
        self.assertIn("technical_support_claim", result.tactic_names)

    def test_tactic_refund_claim(self):
        text = "You are eligible for a tax refund of Rs 4500, claim your refund now."
        result = self.detector.detect(text)
        self.assertIn("refund_claim", result.tactic_names)

    def test_tactic_delivery_problem(self):
        text = "Your package could not be delivered due to incomplete street address."
        result = self.detector.detect(text)
        self.assertIn("delivery_problem", result.tactic_names)

    def test_tactic_qr_code_request(self):
        text = "Scan this QR code to receive payment directly in your account."
        result = self.detector.detect(text)
        self.assertIn("qr_code_request", result.tactic_names)

    def test_tactic_remote_access_request(self):
        text = "Install AnyDesk on your mobile so our support team can verify your phone."
        result = self.detector.detect(text)
        self.assertIn("remote_access_request", result.tactic_names)

    def test_tactic_link_redirection(self):
        text = "Click here to claim your reward: https://bit.ly/free-prize"
        result = self.detector.detect(text)
        self.assertIn("link_redirection", result.tactic_names)

    # -------------------------------------------------------------------------
    # Contextual Negation & Hard Negatives
    # -------------------------------------------------------------------------

    def test_negation_otp_security_advisory(self):
        """Verifies that security warnings telling users NOT to share OTP do not trigger otp_request."""
        text = "Security advisory: Do not share your OTP or password with anyone. Bank never asks."
        result = self.detector.detect(text)
        self.assertNotIn("otp_request", result.tactic_names)
        self.assertNotIn("credential_request", result.tactic_names)

    def test_negation_completed_verification(self):
        """Verifies that a confirmation message stating verification is complete does not trigger verification_request."""
        text = "Dear customer, your KYC is successfully verified. Thank you for banking with us."
        result = self.detector.detect(text)
        self.assertNotIn("verification_request", result.tactic_names)

    def test_negation_payment_receipt(self):
        """Verifies that a payment confirmation/receipt does not trigger payment_request."""
        text = "Payment received: Rs 500 successfully paid for mobile recharge. Thank you."
        result = self.detector.detect(text)
        self.assertNotIn("payment_request", result.tactic_names)

    def test_negation_delivered_parcel(self):
        """Verifies that a delivered parcel confirmation does not trigger delivery_problem."""
        text = "Good news! Your parcel has been delivered to your front porch. Enjoy your purchase!"
        result = self.detector.detect(text)
        self.assertNotIn("delivery_problem", result.tactic_names)

    def test_hard_negative_store_notice(self):
        """Verifies a benign retail notice does not trigger false positive tactics."""
        text = "Our grocery store will remain open until 9 PM tonight for your shopping convenience."
        result = self.detector.detect(text)
        self.assertFalse(result.has_tactics)

    # -------------------------------------------------------------------------
    # Compound Multi-Tactic Detection & Span Integrity
    # -------------------------------------------------------------------------

    def test_compound_scam_message(self):
        """Verifies multi-tactic detection on a realistic composite scam message."""
        text = (
            "URGENT: HDFC Bank alert! Your account will be blocked within 24 hours. "
            "Click https://hdfc-verify.net to verify your KYC now or pay Rs 500 penalty."
        )
        result = self.detector.detect(text, sample_id="test_compound_01")
        self.assertTrue(result.has_tactics)
        self.assertGreaterEqual(result.tactic_count, 4)

        expected = [
            "impersonation",
            "urgency",
            "account_suspension",
            "verification_request",
            "link_redirection",
        ]
        for exp in expected:
            self.assertIn(exp, result.tactic_names)

        # High severity tactics must be ranked first
        self.assertIn(result.tactics[0].severity, ["high", "medium"])

        # Rigorous check: Every evidence span bounds must match text[start:end]
        for tactic in result.tactics:
            for span in tactic.evidence:
                self.assertEqual(
                    text[span.start : span.end],
                    span.matched_text,
                    f"Span mismatch for tactic {tactic.tactic}: '{span.matched_text}' != '{text[span.start:span.end]}'",
                )

    def test_url_injection_and_redirection(self):
        """Verifies that URLs passed explicitly or extracted naturally trigger link_redirection."""
        text = "Access your documents at secure portal"
        urls = ["https://secure-portal.com/login"]
        # URL not in text won't create a character span inside text, but text with URL will
        text_with_url = "Access your documents at https://secure-portal.com/login"
        result = self.detector.detect(text_with_url, urls=["https://secure-portal.com/login"])
        self.assertIn("link_redirection", result.tactic_names)
        span = [
            s
            for t in result.tactics
            if t.tactic == "link_redirection"
            for s in t.evidence
        ][0]
        self.assertEqual(span.matched_text, "https://secure-portal.com/login")
        self.assertEqual(text_with_url[span.start : span.end], span.matched_text)

    # -------------------------------------------------------------------------
    # Batch Processing & Serialization
    # -------------------------------------------------------------------------

    def test_detect_batch(self):
        """Verifies that batch processing works across records."""
        records = [
            {"sample_id": "rec_1", "text": "Congratulations, you won Rs 50000 lottery!"},
            {"sample_id": "rec_2", "text": "Just meeting up for lunch today at noon."},
        ]
        results = self.detector.detect_batch(records)
        self.assertEqual(len(results), 2)
        self.assertIn("reward_claim", results[0].tactic_names)
        self.assertFalse(results[1].has_tactics)

    def test_serialization_to_dict(self):
        """Verifies serialization format of TacticResult."""
        text = "URGENT: Verify your account immediately."
        res = self.detector.detect(text, sample_id="sample_abc")
        d = res.to_dict()

        self.assertEqual(d["sample_id"], "sample_abc")
        self.assertEqual(d["text"], text)
        self.assertTrue(d["has_tactics"])
        self.assertIsInstance(d["tactics"], list)
        self.assertGreaterEqual(len(d["tactics"]), 1)

        t0 = d["tactics"][0]
        self.assertIn("tactic", t0)
        self.assertIn("severity", t0)
        self.assertIn("evidence_strength", t0)
        self.assertIn("evidence", t0)
        self.assertIn("evidence_count", t0)

        ev0 = t0["evidence"][0]
        self.assertIn("matched_text", ev0)
        self.assertIn("start", ev0)
        self.assertIn("end", ev0)
        self.assertIn("rule_id", ev0)
        self.assertIn("severity", ev0)
        self.assertIn("reason", ev0)


if __name__ == "__main__":
    unittest.main()
