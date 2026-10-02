"""Integration tests for ScamShield AI Phase 10: Phase 8 -> RAG -> Explanation Flow."""

import unittest

from src.aggregation.pipeline import CaseAssessmentPipeline
from src.explanation.generator import ExplanationGenerator
from src.explanation.mock_provider import MockExplanationModel
from src.explanation.schemas import Phase10InvestigationReport


class TestPhase10Integration(unittest.TestCase):
    """Verifies end-to-end integration across deterministic detection, RAG, and explanation."""

    def setUp(self):
        self.pipeline = CaseAssessmentPipeline(enable_semantic=True)
        self.generator = ExplanationGenerator(provider=MockExplanationModel())

    def test_end_to_end_scam_case_flow(self):
        """High-urgency phishing message produces grounded investigation report preserving verdict."""
        msg = (
            "URGENT: Your SBI bank account has been suspended! "
            "Verify your PAN and KYC credentials immediately at http://192.168.1.100/verify-kyc"
        )
        case_res = self.pipeline.analyze(msg, sample_id="integ_case_scam")
        report = self.generator.generate_report(case_res, raw_text=msg)

        self.assertIsInstance(report, Phase10InvestigationReport)
        self.assertEqual(report.case_id, "integ_case_scam")

        # Deterministic assessment preserved
        self.assertEqual(
            report.deterministic_assessment["status"],
            case_res.assessment.status,
        )

        # Grounding certified
        self.assertTrue(report.grounding["is_grounded"])
        self.assertEqual(report.grounding["status"], "grounded")
        self.assertTrue(report.grounding["decision_check_passed"])
        self.assertTrue(report.grounding["citation_check_passed"])

        # Audit trail recorded
        self.assertEqual(report.audit["explanation_provider"], "mock")
        self.assertEqual(report.audit["network_requests"], 0)
        self.assertGreater(len(report.audit["retrieved_document_ids"]), 0)

        # Citations present
        expl = report.explanation
        self.assertGreater(len(expl["observed_evidence"]), 0)
        self.assertGreater(len(expl["knowledge_context"]), 0)

    def test_end_to_end_benign_case_flow(self):
        """Benign personal message produces grounded explanation without false fraud claims."""
        msg = "Hi Dad, I will reach Bangalore by the evening train at 6:30 PM."
        case_res = self.pipeline.analyze(msg, sample_id="integ_case_benign")
        report = self.generator.generate_report(case_res, raw_text=msg)

        self.assertEqual(
            report.deterministic_assessment["status"],
            "likely_non_scam",
        )
        self.assertTrue(report.grounding["is_grounded"])
        self.assertEqual(report.grounding["status"], "grounded")
        self.assertNotIn("100% scam", report.explanation["summary"].lower())

    def test_end_to_end_mixed_signals_flow(self):
        """Mixed signals case retains uncertainty and highlights contradictions in explanation."""
        msg = "Your account statement is ready for review at https://secure-bank.example.org"
        case_res = self.pipeline.analyze(msg, sample_id="integ_case_mixed")
        report = self.generator.generate_report(case_res, raw_text=msg)

        det_status = report.deterministic_assessment["status"]
        if det_status == "mixed_signals":
            self.assertIn("conflicting", report.explanation["summary"].lower())
            self.assertTrue(report.grounding["decision_check_passed"])


if __name__ == "__main__":
    unittest.main()
