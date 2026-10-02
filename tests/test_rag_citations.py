"""Unit tests for Phase 10 citation formatting, extraction, and validation."""

import unittest

from src.aggregation.schemas import EvidenceItem
from src.rag.citations import (
    extract_citations,
    format_case_citation,
    format_kb_citation,
    validate_citations,
)
from src.rag.schemas import RetrievedChunk


class TestRAGCitations(unittest.TestCase):
    """Verifies provenance citation formatting, parsing, and authenticity checks."""

    def test_citation_formatting(self):
        """Standard citation formats adhere to strict syntax."""
        c_case = format_case_citation("E1")
        self.assertEqual(c_case, "[CASE:E1]")

        c_kb = format_kb_citation("doc_rbi_financial_safety", "chunk_01")
        self.assertEqual(c_kb, "[KB:doc_rbi_financial_safety:chunk_01]")

    def test_extract_citations_from_text(self):
        """Regex parser extracts all unique CASE and KB tags."""
        sample_text = (
            "We observed urgent pressure [CASE:E1] and an unverified link [CASE:ev_url_02]. "
            "According to official guidance [KB:doc_rbi_financial_safety:chunk_01], banks never "
            "request OTPs over phone calls [KB:doc_credential_otp_theft:chunk_01]."
        )
        res = extract_citations(sample_text)

        self.assertEqual(res["case_citations"], ["[CASE:E1]", ["[CASE:ev_url_02]"][0]])
        self.assertEqual(len(res["case_citations"]), 2)
        self.assertEqual(
            res["kb_citations"],
            ["[KB:doc_credential_otp_theft:chunk_01]", "[KB:doc_rbi_financial_safety:chunk_01]"],
        )

    def test_validate_citations_success(self):
        """Validation passes when all citations match supplied context."""
        text = "Observed [CASE:E1] and official guideline [KB:doc_rbi_financial_safety:chunk_01]."

        valid_evidence = [
            EvidenceItem(
                evidence_id="E1",
                source="phase6_tactic",
                type="tactic",
                name="urgency",
                reason="Immediate deadline",
            )
        ]
        retrieved_chunks = [
            RetrievedChunk(
                document_id="doc_rbi_financial_safety",
                chunk_id="chunk_01",
                title="RBI BE(A)WARE",
                source="RBI",
                topic="banking_fraud",
                similarity_score=0.45,
                text="Never share OTPs.",
                citation_id="[KB:doc_rbi_financial_safety:chunk_01]",
            )
        ]

        is_valid, errors = validate_citations(text, valid_evidence, retrieved_chunks)
        self.assertTrue(is_valid)
        self.assertEqual(len(errors), 0)

    def test_validate_citations_detects_unsupplied_citations(self):
        """Validation fails if text references unsupplied case items or unretrieved chunks."""
        text = "Observed [CASE:E99] and guideline [KB:doc_unretrieved:chunk_05]."

        valid_evidence = [
            EvidenceItem(
                evidence_id="E1",
                source="phase6_tactic",
                type="tactic",
                name="urgency",
                reason="Immediate deadline",
            )
        ]
        retrieved_chunks = [
            RetrievedChunk(
                document_id="doc_rbi_financial_safety",
                chunk_id="chunk_01",
                title="RBI BE(A)WARE",
                source="RBI",
                topic="banking_fraud",
                similarity_score=0.45,
                text="Never share OTPs.",
                citation_id="[KB:doc_rbi_financial_safety:chunk_01]",
            )
        ]

        is_valid, errors = validate_citations(text, valid_evidence, retrieved_chunks)
        self.assertFalse(is_valid)
        self.assertEqual(len(errors), 2)
        self.assertTrue(any("CASE:E99" in e for e in errors))
        self.assertTrue(any("doc_unretrieved:chunk_05" in e for e in errors))


if __name__ == "__main__":
    unittest.main()
