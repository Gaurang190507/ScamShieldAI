"""Canonical data schemas for ScamShield AI tactic detection and evidence extraction.

Defines structured objects for:
- EvidenceSpan: Precise character-offset evidence anchored in the original message.
- DetectedTactic: An identified behavioral tactic with its severity, strength, and evidence spans.
- TacticResult: Complete tactic evaluation container for a message.
"""

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional


@dataclass
class EvidenceSpan:
    """Represents a specific textual evidence span that triggered a tactic rule."""

    matched_text: str
    start: int
    end: int
    rule_id: str
    severity: str
    reason: str

    def to_dict(self) -> Dict[str, Any]:
        """Serializes evidence span to standard dictionary format."""
        return {
            "matched_text": self.matched_text,
            "start": self.start,
            "end": self.end,
            "rule_id": self.rule_id,
            "severity": self.severity,
            "reason": self.reason,
        }


@dataclass
class DetectedTactic:
    """Represents an identified scam tactic along with supporting evidence spans."""

    tactic: str
    severity: str  # "low", "medium", "high"
    evidence_strength: str  # "low", "medium", "high"
    evidence: List[EvidenceSpan] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        """Serializes detected tactic to standard dictionary format."""
        return {
            "tactic": self.tactic,
            "severity": self.severity,
            "evidence_strength": self.evidence_strength,
            "evidence": [span.to_dict() for span in self.evidence],
            "evidence_count": len(self.evidence),
        }


@dataclass
class TacticResult:
    """Unified container for all tactics detected in an analyzed message."""

    text: str
    tactics: List[DetectedTactic] = field(default_factory=list)
    sample_id: Optional[str] = None

    @property
    def tactic_count(self) -> int:
        """Returns the number of distinct tactics detected."""
        return len(self.tactics)

    @property
    def has_tactics(self) -> bool:
        """Returns True if at least one tactic was detected."""
        return len(self.tactics) > 0

    @property
    def tactic_names(self) -> List[str]:
        """Returns a list of tactic name strings."""
        return [t.tactic for t in self.tactics]

    def to_dict(self) -> Dict[str, Any]:
        """Serializes tactic analysis result to standard dictionary format."""
        res: Dict[str, Any] = {
            "sample_id": self.sample_id,
            "text": self.text,
            "tactics": [t.to_dict() for t in self.tactics],
            "tactic_count": self.tactic_count,
            "has_tactics": self.has_tactics,
        }
        return res
