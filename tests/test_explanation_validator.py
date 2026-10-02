"""Unit tests for Phase 10 post-generation GroundingValidator."""

import unittest

from src.explanation.schemas import ExplanationRequest, ExplanationResponse
from src.explanation.validator import GroundingValidator


class TestExplanationValidator(unittest.TestCase):
    """Verifies evidence grounding checks, citation audits, and decision immutability."""

    def setUp(self):
        self.validator = GroundingValidator()
        self.valid_request = ExplanationRequest(
            case_id="case_valid_01",
            deterministic_result={
                "status": "likely_scam",
                "evidence_level": "high",
                "signal_consistency": "strong_agreement",
            },
            tactics=["urgency", "impersonation"],
            evidence=[
                {"evidence_id": "E1", "name": "urgency", "reason": "Immediate 30 min deadline", "citation_id": "[CASE:E1]"},
                {"evidence_id": "E2", "name": "impersonation", "reason": "Spoofed bank official", "citation_id": "[CASE:E2]"},
            ],
            retrieved_knowledge=[
                {
                    "document_id": "doc_i4c_citizen_guidelines",
                    "chunk_id": "chunk_01",
                    "citation_id": "[KB:doc_i4c_citizen_guidelines:chunk_01]",
                    "title": "I4C Guidelines",
                    "text": "Never share credentials.",
                }
            ],
        )

    def test_validation_passes_on_grounded_response(self):
        """Valid response with matched citations and tactics passes validation."""
        response = ExplanationResponse(
            summary="The message shows characteristics of an impersonation scam.",
            decision_context="Multiple high-risk indicators were detected.",
            observed_evidence=[
                {"evidence": "Immediate 30 min deadline", "source": "case", "citation": "[CASE:E1]"}
            ],
            tactic_explanations=[
                {"tactic": "urgency", "explanation": "Urgent deadline observed."}
            ],
            knowledge_context=[
                {
                    "claim": "I4C Guidelines: Never share credentials.",
                    "source_document": "doc_i4c_citizen_guidelines",
                    "chunk_id": "chunk_01",
                    "citation": "[KB:doc_i4c_citizen_guidelines:chunk_01]",
                }
            ],
            recommended_action="Do not click the link.",
            confidence_statement="High confidence based on case findings.",
        )

        res = self.validator.validate(self.valid_request, response)
        self.assertTrue(res.is_grounded)
        self.assertEqual(res.status, "grounded")
        self.assertEqual(len(res.errors), 0)

    def test_validator_detects_invented_tactics(self):
        """Validator rejects explanation that introduces unsupplied tactics."""
        response = ExplanationResponse(
            summary="Scam detected.",
            decision_context="Tactics detected.",
            observed_evidence=[],
            tactic_explanations=[
                # "crypto_investment" was NOT in self.valid_request.tactics!
                {"tactic": "crypto_investment", "explanation": "Promised high returns"}
            ],
            knowledge_context=[],
        )

        res = self.validator.validate(self.valid_request, response)
        self.assertFalse(res.is_grounded)
        self.assertFalse(res.tactic_check_passed)
        self.assertTrue(any("Invented tactic" in e for e in res.errors))

    def test_validator_detects_decision_override_on_scam(self):
        """Validator rejects explanation claiming a 'likely_scam' message is safe."""
        response = ExplanationResponse(
            # Contradiction: claiming it is completely safe!
            summary="Do not worry, this is completely safe and authentic.",
            decision_context="No threat detected.",
            observed_evidence=[],
            tactic_explanations=[],
            knowledge_context=[],
        )

        res = self.validator.validate(self.valid_request, response)
        self.assertFalse(res.is_grounded)
        self.assertFalse(res.decision_check_passed)
        self.assertTrue(any("Decision override violation" in e for e in res.errors))

    def test_validator_detects_invalid_knowledge_citation(self):
        """Validator flags citations to unretrieved knowledge chunks."""
        response = ExplanationResponse(
            summary="Scam detected.",
            decision_context="Guidance cited.",
            observed_evidence=[],
            tactic_explanations=[],
            knowledge_context=[
                {
                    "claim": "Unretrieved claim",
                    # doc_fake was NOT retrieved in valid_request!
                    "source_document": "doc_fake_source",
                    "chunk_id": "chunk_99",
                    "citation": "[KB:doc_fake_source:chunk_99]",
                }
            ],
        )

        res = self.validator.validate(self.valid_request, response)
        self.assertFalse(res.is_grounded)
        self.assertFalse(res.citation_check_passed)
        self.assertTrue(any("Invalid knowledge source" in e for e in res.errors))


if __name__ == "__main__":
    unittest.main()
