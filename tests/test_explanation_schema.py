"""Unit tests for Phase 10 Explanation schemas and serialization contracts."""

import unittest

from src.explanation.schemas import (
    ExplanationRequest,
    ExplanationResponse,
    GroundingValidationResult,
    KnowledgeContextItem,
    ObservedEvidenceItem,
    Phase10InvestigationReport,
    TacticExplanationItem,
)


class TestExplanationSchema(unittest.TestCase):
    """Verifies schema structure, typing, and serialization behavior."""

    def test_explanation_request_serialization(self):
        """ExplanationRequest serializes completely to dictionary."""
        req = ExplanationRequest(
            case_id="case_test_01",
            deterministic_result={
                "status": "likely_scam",
                "evidence_level": "high",
                "signal_consistency": "strong_agreement",
            },
            tactics=["urgency", "payment_request"],
            evidence=[{"evidence_id": "E1", "name": "urgency", "citation_id": "[CASE:E1]"}],
            retrieved_knowledge=[{"document_id": "doc_rbi_financial_safety", "chunk_id": "chunk_01"}],
            raw_text="Urgent: send money now",
        )
        d = req.to_dict()
        self.assertEqual(d["case_id"], "case_test_01")
        self.assertEqual(d["deterministic_result"]["status"], "likely_scam")
        self.assertEqual(len(d["tactics"]), 2)
        self.assertEqual(d["raw_text"], "Urgent: send money now")

    def test_explanation_response_serialization(self):
        """ExplanationResponse serializes and preserves nested items."""
        resp = ExplanationResponse(
            summary="Test summary",
            decision_context="Test context",
            observed_evidence=[{"evidence": "Urgency observed", "source": "case", "citation": "[CASE:E1]"}],
            tactic_explanations=[{"tactic": "urgency", "explanation": "Urgent deadline observed"}],
            knowledge_context=[{"claim": "Official guidance", "source_document": "doc_01", "chunk_id": "c1"}],
            uncertainties=["None noted"],
            recommended_action="Do not click link",
            confidence_statement="High confidence based on multiple signals",
        )
        d = resp.to_dict()
        self.assertEqual(d["summary"], "Test summary")
        self.assertEqual(len(d["observed_evidence"]), 1)
        self.assertEqual(d["observed_evidence"][0]["citation"], "[CASE:E1]")
        self.assertEqual(len(d["tactic_explanations"]), 1)

    def test_investigation_report_contract(self):
        """Phase10InvestigationReport conforms to the required unified output specification."""
        rep = Phase10InvestigationReport(
            case_id="case_999",
            deterministic_assessment={"status": "likely_scam", "evidence_level": "high"},
            explanation={"summary": "Scam summary"},
            grounding={"is_grounded": True, "status": "grounded"},
            audit={"provider": "mock", "prompt_version": "1.0.0"},
        )
        d = rep.to_dict()
        self.assertEqual(d["case_id"], "case_999")
        self.assertIn("deterministic_assessment", d)
        self.assertIn("explanation", d)
        self.assertIn("grounding", d)
        self.assertIn("audit", d)


if __name__ == "__main__":
    unittest.main()
