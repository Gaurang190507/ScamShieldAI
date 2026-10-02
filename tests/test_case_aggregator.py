"""Unit tests for ScamShield AI Phase 8 Multi-Signal Risk Aggregator & Forensic Audit."""

import json
import unittest
from pathlib import Path

from src.aggregation.schemas import (
    CaseAssessmentInput,
    CaseAssessmentResult,
    EvidenceItem,
    AssessmentSummary,
    ExplanationObject,
    AuditObject,
)
from src.aggregation.normalizer import SignalNormalizer
from src.aggregation.aggregator import RiskAggregator
from src.aggregation.pipeline import CaseAssessmentPipeline


class TestCaseAggregator(unittest.TestCase):
    """Test suite for Phase 8 multi-signal aggregation logic and forensic audit."""

    def setUp(self):
        """Set up fresh aggregator instance."""
        self.aggregator = RiskAggregator()

    def test_strong_multisignal_scam(self):
        """Test case where classifier, severe tactics, and URL risk all indicate scam."""
        case_input = CaseAssessmentInput(
            sample_id="test_001",
            text="URGENT: Your bank account is locked! Click http://192.168.1.1/login to verify your password immediately.",
            text_classifier_probability=0.95,
            text_classifier_threshold=0.30,
            text_classifier_label="scam",
            url_count=1,
            url_risk_score_max=0.85,
            url_risk_score_mean=0.85,
            url_signals=[
                {
                    "signal": "ip_based_hostname",
                    "severity": "high",
                    "score": 0.40,
                    "url": "http://192.168.1.1/login",
                    "reason": "Direct IP address host used.",
                }
            ],
            detected_tactics=["account_suspension", "credential_request"],
            tactic_evidence=[
                {
                    "tactic": "account_suspension",
                    "matched_text": "account is locked",
                    "start": 18,
                    "end": 35,
                    "severity": "high",
                    "reason": "Account suspension threat.",
                },
                {
                    "tactic": "credential_request",
                    "matched_text": "verify your password",
                    "start": 74,
                    "end": 94,
                    "severity": "high",
                    "reason": "Explicit credential harvesting.",
                },
            ],
            top1_similarity=0.82,
            semantic_novelty_score=0.18,
            semantic_status="similar_to_known",
        )

        result = self.aggregator.aggregate(case_input)

        self.assertEqual(result.assessment.status, "likely_scam")
        self.assertEqual(result.assessment.evidence_level, "high")
        self.assertEqual(result.assessment.signal_consistency, "strong_agreement")
        self.assertIn("rule_strong_scam", result.audit.final_decision_rule)
        self.assertFalse(result.audit.network_access)
        self.assertFalse(result.audit.phase5_used)
        self.assertGreater(result.audit.evidence_count, 0)
        self.assertGreater(len(result.supporting_signals), 0)

    def test_clean_legitimate_message(self):
        """Test unanimous clean legitimate message with low text score and zero tactics."""
        case_input = CaseAssessmentInput(
            sample_id="test_002",
            text="Hey are we still meeting for lunch today at noon?",
            text_classifier_probability=0.02,
            text_classifier_threshold=0.30,
            text_classifier_label="non_scam",
            url_count=0,
            url_risk_score_max=0.0,
            url_signals=[],
            detected_tactics=[],
            tactic_evidence=[],
            top1_similarity=0.65,
            semantic_novelty_score=0.35,
            semantic_status="moderately_novel",
        )

        result = self.aggregator.aggregate(case_input)

        self.assertEqual(result.assessment.status, "likely_non_scam")
        self.assertEqual(result.assessment.evidence_level, "low")
        self.assertEqual(result.assessment.signal_consistency, "strong_agreement")
        self.assertEqual(result.audit.final_decision_rule, "rule_clean_non_scam_unanimous")
        self.assertFalse(result.audit.network_access)
        self.assertFalse(result.audit.phase5_used)
        self.assertIn("non-scam pattern", result.explanation.reasons[0])

    def test_contradiction_high_classifier_clean_tactics(self):
        """Test contradiction: text classifier flags scam (0.85), but zero tactics and clean URL."""
        case_input = CaseAssessmentInput(
            sample_id="test_003",
            text="Win free cash prize today with promo code special offer.",
            text_classifier_probability=0.85,
            text_classifier_threshold=0.30,
            text_classifier_label="scam",
            url_count=0,
            url_risk_score_max=0.0,
            url_signals=[],
            detected_tactics=[],
            tactic_evidence=[],
        )

        result = self.aggregator.aggregate(case_input)

        self.assertEqual(result.assessment.status, "mixed_signals")
        self.assertEqual(result.assessment.signal_consistency, "mixed")
        self.assertEqual(
            result.audit.final_decision_rule,
            "rule_contradiction_classifier_scam_clean_behavior",
        )
        self.assertGreater(len(result.explanation.cautions), 0)
        self.assertIn("disagree", result.explanation.cautions[0])

    def test_contradiction_benign_text_high_url_threat(self):
        """Test contradiction: benign text (0.05), but embedded high-risk IP URL."""
        case_input = CaseAssessmentInput(
            sample_id="test_004",
            text="Please see the team meeting notes at http://10.0.0.1/notes",
            text_classifier_probability=0.05,
            text_classifier_threshold=0.30,
            text_classifier_label="non_scam",
            url_count=1,
            url_risk_score_max=0.65,
            url_signals=[
                {
                    "signal": "ip_based_hostname",
                    "severity": "high",
                    "score": 0.40,
                    "url": "http://10.0.0.1/notes",
                    "reason": "Direct IP address host.",
                }
            ],
            detected_tactics=["link_redirection"],
            tactic_evidence=[],
        )

        result = self.aggregator.aggregate(case_input)

        self.assertEqual(result.assessment.status, "mixed_signals")
        self.assertEqual(result.assessment.signal_consistency, "mixed")
        self.assertIn("contradiction", result.audit.final_decision_rule)

    def test_semantic_novelty_is_not_scam(self):
        """Test that high semantic novelty alone does NOT cause a scam assessment."""
        case_input = CaseAssessmentInput(
            sample_id="test_005",
            text="Quantum computing entanglement matrix optimization completed successfully.",
            text_classifier_probability=0.08,
            text_classifier_threshold=0.30,
            text_classifier_label="non_scam",
            url_count=0,
            url_risk_score_max=0.0,
            detected_tactics=[],
            top1_similarity=0.25,
            semantic_novelty_score=0.75,  # High novelty!
            semantic_status="potentially_novel",
        )

        result = self.aggregator.aggregate(case_input)

        # Must NOT be evaluated as scam purely due to novelty
        self.assertEqual(result.assessment.status, "likely_non_scam")
        # Caution must clarify that novelty is not scam guilt
        caution_texts = " ".join(result.explanation.cautions)
        self.assertIn("not definitive fraud", caution_texts)

    def test_critical_tactic_exploitation_override(self):
        """Test that critical credentials/OTP theft triggers exploitation override even with lower classifier score."""
        case_input = CaseAssessmentInput(
            sample_id="test_006",
            text="Please share your one-time password OTP immediately to complete verification.",
            text_classifier_probability=0.22,  # Below standard threshold
            text_classifier_threshold=0.30,
            text_classifier_label="non_scam",
            url_count=0,
            url_risk_score_max=0.0,
            detected_tactics=["otp_request"],
            tactic_evidence=[
                {
                    "tactic": "otp_request",
                    "matched_text": "share your one-time password OTP",
                    "start": 7,
                    "end": 39,
                    "severity": "high",
                    "reason": "OTP harvesting.",
                }
            ],
        )

        result = self.aggregator.aggregate(case_input)

        self.assertEqual(result.assessment.status, "likely_scam")
        self.assertEqual(result.assessment.evidence_level, "high")
        self.assertEqual(
            result.audit.final_decision_rule,
            "rule_critical_tactics_exploitation_override",
        )

    def test_empty_input_handling(self):
        """Test handling of empty or whitespace text."""
        case_input = CaseAssessmentInput(
            sample_id="test_007",
            text="   ",
            text_classifier_probability=None,
        )

        result = self.aggregator.aggregate(case_input)

        self.assertEqual(result.assessment.status, "insufficient_evidence")
        self.assertEqual(result.audit.final_decision_rule, "rule_empty_content")
        self.assertEqual(result.assessment.evidence_level, "low")

    def test_audit_object_invariants(self):
        """Verify strict compliance guarantees in the forensic audit object."""
        case_input = CaseAssessmentInput(
            sample_id="test_008",
            text="Hello friend.",
            text_classifier_probability=0.01,
            text_classifier_threshold=0.30,
            text_classifier_label="non_scam",
        )

        result = self.aggregator.aggregate(case_input)

        # Audit invariants:
        self.assertFalse(result.audit.network_access)
        self.assertFalse(result.audit.external_lookup)
        self.assertFalse(result.audit.phase5_used)  # Explicitly excluded
        self.assertTrue(result.audit.phase4_used)
        self.assertTrue(result.audit.phase6_used)
        self.assertIsInstance(result.audit.timestamp, str)
        self.assertIsInstance(result.audit.final_decision_rule, str)
        self.assertGreaterEqual(result.audit.evidence_count, 0)
        self.assertGreaterEqual(result.audit.contradiction_count, 0)

    def test_serialization_to_dict_and_json(self):
        """Verify complete serializability of CaseAssessmentResult to valid JSON."""
        case_input = CaseAssessmentInput(
            sample_id="test_009",
            text="Your account is locked. Visit http://evil.com",
            text_classifier_probability=0.88,
            text_classifier_threshold=0.30,
            text_classifier_label="scam",
            url_count=1,
            url_risk_score_max=0.45,
            detected_tactics=["account_suspension", "link_redirection"],
            top1_similarity=0.74,
            semantic_novelty_score=0.26,
            semantic_status="similar_to_known",
        )

        result = self.aggregator.aggregate(case_input)
        d = result.to_dict()

        # Check required schema keys
        self.assertIn("sample_id", d)
        self.assertIn("assessment", d)
        self.assertIn("signals", d)
        self.assertIn("evidence", d)
        self.assertIn("supporting_signals", d)
        self.assertIn("contradicting_signals", d)
        self.assertIn("explanation", d)
        self.assertIn("audit", d)

        # Verify JSON dump roundtrip
        json_str = json.dumps(d)
        self.assertIsInstance(json_str, str)
        parsed = json.loads(json_str)
        self.assertEqual(parsed["sample_id"], "test_009")
        self.assertEqual(parsed["assessment"]["status"], "likely_scam")

    def test_pipeline_end_to_end(self):
        """Verify CaseAssessmentPipeline runs end-to-end on arbitrary text without network."""
        pipeline = CaseAssessmentPipeline(enable_semantic=False)

        text = "URGENT: Your account has been suspended! Send money immediately."
        result = pipeline.analyze(text=text, sample_id="pipeline_e2e_01")

        self.assertIsInstance(result, CaseAssessmentResult)
        self.assertIn(result.assessment.status, ["likely_scam", "mixed_signals"])
        self.assertFalse(result.audit.network_access)
        self.assertFalse(result.audit.phase5_used)
        self.assertGreater(len(result.evidence), 0)


if __name__ == "__main__":
    unittest.main()
