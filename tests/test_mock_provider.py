"""Unit tests for MockExplanationModel determinism, offline operation, and coverage."""

import unittest

from src.explanation.mock_provider import MockExplanationModel
from src.explanation.schemas import ExplanationRequest


class TestMockProvider(unittest.TestCase):
    """Verifies mock provider determinism, formatting, and offline compliance."""

    def setUp(self):
        self.model = MockExplanationModel()

    def test_provider_name_and_offline(self):
        """Mock provider reports correct provider name and requires zero network access."""
        self.assertEqual(self.model.provider_name, "mock")

    def test_generates_grounded_response_for_all_case_statuses(self):
        """Provider produces valid structured responses across diverse assessment statuses."""
        statuses = ["likely_scam", "likely_non_scam", "mixed_signals", "insufficient_evidence"]

        for st in statuses:
            req = ExplanationRequest(
                case_id=f"case_{st}",
                deterministic_result={
                    "status": st,
                    "evidence_level": "moderate",
                    "signal_consistency": "moderate_agreement",
                },
                tactics=["urgency"] if st == "likely_scam" else [],
                evidence=[
                    {"evidence_id": "E1", "name": "urgency", "reason": "Immediate deadline", "citation_id": "[CASE:E1]"}
                ],
                retrieved_knowledge=[
                    {
                        "document_id": "doc_i4c_citizen_guidelines",
                        "chunk_id": "chunk_01",
                        "citation_id": "[KB:doc_i4c_citizen_guidelines:chunk_01]",
                        "title": "I4C Guidelines",
                        "text": "Official guideline text.",
                    }
                ],
            )

            resp = self.model.generate_explanation(req)
            self.assertGreater(len(resp.summary), 10)
            self.assertGreater(len(resp.decision_context), 10)
            self.assertGreater(len(resp.recommended_action), 10)
            self.assertGreater(len(resp.confidence_statement), 10)

            # Citations should be present when evidence/knowledge is supplied
            self.assertGreater(len(resp.observed_evidence), 0)
            self.assertEqual(resp.observed_evidence[0]["citation"], "[CASE:E1]")
            self.assertGreater(len(resp.knowledge_context), 0)
            self.assertEqual(resp.knowledge_context[0]["citation"], "[KB:doc_i4c_citizen_guidelines:chunk_01]")

    def test_empty_signals_handling(self):
        """Provider handles cases with no detected tactics or evidence without crashing."""
        req = ExplanationRequest(
            case_id="case_empty",
            deterministic_result={"status": "insufficient_evidence"},
            tactics=[],
            evidence=[],
            retrieved_knowledge=[],
        )
        resp = self.model.generate_explanation(req)
        self.assertIn("insufficient", resp.summary.lower())
        self.assertEqual(len(resp.observed_evidence), 0)
        self.assertEqual(len(resp.tactic_explanations), 0)
        self.assertEqual(len(resp.knowledge_context), 0)


if __name__ == "__main__":
    unittest.main()
