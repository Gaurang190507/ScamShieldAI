"""Unit tests for ScamShield AI Phase 6 EvidenceEngine.

Verifies:
- Evidence span boundary validation (text[start:end] == matched_text)
- Out-of-bounds offset detection
- Overlap resolution and deduplication
- Tactic assembly and evidence strength logic
"""

import unittest

from src.tactics.evidence import EvidenceEngine
from src.tactics.schemas import EvidenceSpan


class TestEvidenceEngine(unittest.TestCase):
    """Test suite for EvidenceEngine logic."""

    def test_validate_span_exact_match(self):
        """Verifies that an exact substring match validates to True."""
        text = "URGENT: Please verify your bank account now."
        # "URGENT" starts at 0, ends at 6
        span = EvidenceSpan(
            matched_text="URGENT",
            start=0,
            end=6,
            rule_id="urg_001",
            severity="medium",
            reason="Urgency keyword",
        )
        self.assertTrue(EvidenceEngine.validate_span(text, span))

    def test_validate_span_mismatched_text(self):
        """Verifies that a mismatch between matched_text and text[start:end] returns False."""
        text = "URGENT: Please verify your bank account now."
        span = EvidenceSpan(
            matched_text="URGENTLY",
            start=0,
            end=6,
            rule_id="urg_001",
            severity="medium",
            reason="Urgency keyword",
        )
        self.assertFalse(EvidenceEngine.validate_span(text, span))

    def test_validate_span_out_of_bounds(self):
        """Verifies that out-of-bounds start/end offsets return False."""
        text = "Hello world"
        # Negative start
        span_neg = EvidenceSpan(
            matched_text="Hello",
            start=-1,
            end=4,
            rule_id="r1",
            severity="low",
            reason="r",
        )
        self.assertFalse(EvidenceEngine.validate_span(text, span_neg))

        # End beyond len(text)
        span_overflow = EvidenceSpan(
            matched_text="world",
            start=6,
            end=20,
            rule_id="r2",
            severity="low",
            reason="r",
        )
        self.assertFalse(EvidenceEngine.validate_span(text, span_overflow))

        # Start >= End
        span_inverted = EvidenceSpan(
            matched_text="",
            start=5,
            end=5,
            rule_id="r3",
            severity="low",
            reason="r",
        )
        self.assertFalse(EvidenceEngine.validate_span(text, span_inverted))

    def test_deduplicate_spans_empty(self):
        """Verifies that deduplicating empty list returns empty list."""
        self.assertEqual(EvidenceEngine.deduplicate_spans([]), [])

    def test_deduplicate_spans_non_overlapping(self):
        """Verifies that non-overlapping spans are preserved in offset order."""
        s1 = EvidenceSpan("first", 0, 5, "r1", "medium", "reason 1")
        s2 = EvidenceSpan("second", 10, 16, "r2", "medium", "reason 2")
        result = EvidenceEngine.deduplicate_spans([s2, s1])
        self.assertEqual(len(result), 2)
        self.assertEqual(result[0].start, 0)
        self.assertEqual(result[1].start, 10)

    def test_deduplicate_spans_overlapping_keeps_longer(self):
        """Verifies that when two spans overlap, the longer one is retained."""
        # e.g., "immediately" vs "will be disconnected immediately"
        s_short = EvidenceSpan("immediately", 20, 31, "urg_001", "medium", "short")
        s_long = EvidenceSpan(
            "disconnected immediately", 7, 31, "urg_002", "medium", "longer"
        )
        result = EvidenceEngine.deduplicate_spans([s_short, s_long])
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0].matched_text, "disconnected immediately")

    def test_deduplicate_spans_subsumed(self):
        """Verifies that a span completely contained inside another is dropped."""
        s_outer = EvidenceSpan("State Bank of India", 0, 19, "imp_001", "medium", "full")
        s_inner = EvidenceSpan("Bank", 6, 10, "imp_002", "medium", "inner")
        result = EvidenceEngine.deduplicate_spans([s_outer, s_inner])
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0].matched_text, "State Bank of India")

    def test_deduplicate_spans_identical_bounds(self):
        """Verifies that identical duplicate spans are deduplicated to one."""
        s1 = EvidenceSpan("SBI", 0, 3, "r1", "medium", "reason 1")
        s2 = EvidenceSpan("SBI", 0, 3, "r2", "high", "reason 2")
        result = EvidenceEngine.deduplicate_spans([s1, s2])
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0].matched_text, "SBI")

    def test_assemble_tactic_empty_spans(self):
        """Verifies assemble_tactic returns None if no spans are provided."""
        res = EvidenceEngine.assemble_tactic("urgency", "medium", [])
        self.assertIsNone(res)

    def test_assemble_tactic_single_span(self):
        """Verifies assemble_tactic builds DetectedTactic correctly."""
        s = EvidenceSpan("URGENT", 0, 6, "urg_001", "medium", "reason")
        tactic = EvidenceEngine.assemble_tactic("urgency", "medium", [s])
        self.assertIsNotNone(tactic)
        self.assertEqual(tactic.tactic, "urgency")
        self.assertEqual(tactic.severity, "medium")
        self.assertEqual(tactic.evidence_strength, "medium")
        self.assertEqual(len(tactic.evidence), 1)

    def test_assemble_tactic_multiple_spans_strengthens_evidence(self):
        """Verifies that multiple evidence spans upgrade evidence_strength to high."""
        s1 = EvidenceSpan("immediately", 0, 11, "urg_001", "medium", "reason 1")
        s2 = EvidenceSpan("within 2 hours", 15, 29, "urg_002", "medium", "reason 2")
        tactic = EvidenceEngine.assemble_tactic("urgency", "medium", [s1, s2])
        self.assertIsNotNone(tactic)
        self.assertEqual(tactic.evidence_strength, "high")
        self.assertEqual(len(tactic.evidence), 2)


if __name__ == "__main__":
    unittest.main()
