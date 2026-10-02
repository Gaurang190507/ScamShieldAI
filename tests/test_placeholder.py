"""Verification test for ScamShield AI modular components."""

import unittest
from src.rules.tactic_patterns import RuleDetector
from src.risk_engine.scoring import RiskEngine, RiskLevel


class TestScamShieldComponents(unittest.TestCase):
    def setUp(self):
        self.detector = RuleDetector()
        self.engine = RiskEngine()

    def test_benign_message_uncertainty(self):
        """Benign message should result in Insufficient evidence rather than claiming safe."""
        benign_text = "Hello, your order will be delivered tomorrow afternoon."
        tactics_benign = self.detector.detect_tactics(benign_text)
        assessment_benign = self.engine.evaluate(tactics_benign)
        self.assertEqual(assessment_benign["risk_level"], RiskLevel.INSUFFICIENT_EVIDENCE.value)

    def test_high_risk_tactics_combination(self):
        """Combination of urgency and credential harvesting yields High risk."""
        suspect_text = "URGENT: Your account is suspended. Send your OTP immediately to verify."
        tactics_suspect = self.detector.detect_tactics(suspect_text)
        assessment_suspect = self.engine.evaluate(tactics_suspect)
        self.assertIn("urgency", tactics_suspect)
        self.assertIn("otp_or_credentials", tactics_suspect)
        self.assertEqual(assessment_suspect["risk_level"], RiskLevel.HIGH_RISK.value)


if __name__ == "__main__":
    unittest.main()
