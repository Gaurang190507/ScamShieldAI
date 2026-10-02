"""Evidence extraction, deduplication, and verification engine for ScamShield AI.

Ensures that:
1. Every evidence span is anchored directly to verbatim text at valid offsets.
2. Character bounds text[start:end] strictly equal matched_text.
3. Overlapping or subsumed spans for the same tactic are cleanly resolved.
4. Spans are ordered sequentially by appearance in the message.
"""

from typing import Dict, List, Optional
from .schemas import DetectedTactic, EvidenceSpan


class EvidenceEngine:
    """Extracts, validates, and deduplicates evidence spans for detected tactics."""

    @staticmethod
    def validate_span(text: str, span: EvidenceSpan) -> bool:
        """Verifies that the evidence span bounds exactly correspond to the original text.

        Args:
            text: Original message string.
            span: Candidate EvidenceSpan.

        Returns:
            True if 0 <= start < end <= len(text) and text[start:end] == span.matched_text.
        """
        if not (0 <= span.start < span.end <= len(text)):
            return False
        return text[span.start : span.end] == span.matched_text

    @staticmethod
    def deduplicate_spans(spans: List[EvidenceSpan]) -> List[EvidenceSpan]:
        """Resolves overlapping or subsumed spans for a single tactic.

        If span A and span B overlap, retains the longer, more specific span.
        If spans have identical length and bounds, retains the first.

        Args:
            spans: List of candidate EvidenceSpan objects.

        Returns:
            Sorted, non-overlapping list of EvidenceSpan objects.
        """
        if not spans:
            return []

        # Sort primarily by start offset ascending, then by span length descending
        sorted_spans = sorted(spans, key=lambda s: (s.start, -(s.end - s.start)))
        resolved: List[EvidenceSpan] = []

        for current in sorted_spans:
            if not resolved:
                resolved.append(current)
                continue

            last = resolved[-1]

            # Check for overlap: current starts before last ends
            if current.start < last.end:
                # If current extends beyond last, check which is longer
                curr_len = current.end - current.start
                last_len = last.end - last.start
                if curr_len > last_len:
                    # Replace last with current because current is more specific
                    resolved[-1] = current
                # Otherwise, current is subsumed or shorter, so skip it
                continue
            else:
                resolved.append(current)

        return resolved

    @classmethod
    def assemble_tactic(
        cls,
        tactic_name: str,
        severity: str,
        raw_spans: List[EvidenceSpan],
        base_strength: str = "medium",
    ) -> Optional[DetectedTactic]:
        """Assembles a DetectedTactic from raw evidence spans after deduplication.

        Args:
            tactic_name: Canonical tactic identifier.
            severity: Tactic severity ("low", "medium", "high").
            raw_spans: List of candidate EvidenceSpan objects.
            base_strength: Base evidence strength ("low", "medium", "high").

        Returns:
            DetectedTactic object if valid evidence spans exist, else None.
        """
        deduped = cls.deduplicate_spans(raw_spans)
        if not deduped:
            return None

        # Determine aggregate evidence strength
        strength = base_strength
        if len(deduped) >= 2 or any(s.severity == "high" for s in deduped):
            strength = "high"

        return DetectedTactic(
            tactic=tactic_name,
            severity=severity,
            evidence_strength=strength,
            evidence=deduped,
        )
