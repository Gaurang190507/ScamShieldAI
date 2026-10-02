"""Canonical data schemas for ScamShield AI Phase 8 Multi-Signal Risk Aggregation & Forensic Audit.

Defines structured objects for:
- EvidenceItem: Unified atomic evidence representation across all detection phases.
- AssessmentSummary: High-level case status, evidence level, and signal consistency.
- ExplanationObject: Deterministic summary, reasons, and cautionary notes.
- AuditObject: Complete forensic verification record ensuring zero network/external access.
- CaseAssessmentInput: Normalized input container fed into the aggregator.
- CaseAssessmentResult: Complete structured case evaluation output.
"""

from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional


@dataclass
class EvidenceItem:
    """Represents a discrete piece of evidence extracted from any upstream component."""

    evidence_id: str
    source: str  # "phase3_classifier", "phase4_url", "phase6_tactic", "phase7_similarity"
    type: str  # "classification", "url_signal", "tactic", "semantic_context"
    name: str  # e.g., "payment_request", "ip_based_hostname", "scam_probability"
    value: Optional[Any] = None
    text: Optional[str] = None  # Verbatim matched substring for textual evidence
    start: Optional[int] = None
    end: Optional[int] = None
    url: Optional[str] = None
    strength: str = "supporting"  # "supporting", "contradicting", "contextual", "weak"
    reason: str = ""

    def to_dict(self) -> Dict[str, Any]:
        """Serializes evidence item to dictionary."""
        d: Dict[str, Any] = {
            "evidence_id": self.evidence_id,
            "source": self.source,
            "type": self.type,
            "name": self.name,
            "strength": self.strength,
            "reason": self.reason,
        }
        if self.value is not None:
            d["value"] = self.value
        if self.text is not None:
            d["text"] = self.text
        if self.start is not None and self.end is not None:
            d["start"] = self.start
            d["end"] = self.end
        if self.url is not None:
            d["url"] = self.url
        return d


@dataclass
class AssessmentSummary:
    """High-level case assessment categorizations."""

    status: str  # "likely_scam", "likely_non_scam", "mixed_signals", "insufficient_evidence"
    evidence_level: str  # "high", "moderate", "low"
    signal_consistency: str  # "strong_agreement", "moderate_agreement", "mixed", "insufficient"

    def to_dict(self) -> Dict[str, Any]:
        """Serializes assessment summary to dictionary."""
        return asdict(self)


@dataclass
class ExplanationObject:
    """Deterministic, template-generated explanation of the assessment."""

    summary: str
    reasons: List[str] = field(default_factory=list)
    cautions: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        """Serializes explanation to dictionary."""
        return asdict(self)


@dataclass
class AuditObject:
    """Forensic audit trail guaranteeing pipeline compliance and determinism."""

    phase3_used: bool = True
    phase4_used: bool = True
    phase5_used: bool = False  # Explicitly False: Phase 5 was an experiment, excluded from runtime inference
    phase6_used: bool = True
    phase7_used: bool = True
    network_access: bool = False  # Guaranteed offline
    external_lookup: bool = False  # Zero WHOIS/DNS/API calls
    final_decision_rule: str = ""
    evidence_count: int = 0
    contradiction_count: int = 0
    timestamp: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )

    def to_dict(self) -> Dict[str, Any]:
        """Serializes audit trail to dictionary."""
        return asdict(self)


@dataclass
class CaseAssessmentInput:
    """Normalized input container aggregating all upstream module signals for a case."""

    sample_id: Optional[str] = None
    text: str = ""

    # Phase 3 Text Classifier outputs
    text_classifier_probability: Optional[float] = None
    text_classifier_threshold: Optional[float] = 0.30
    text_classifier_label: Optional[str] = None

    # Phase 4 URL Analysis outputs
    url_count: int = 0
    url_risk_score_max: float = 0.0
    url_risk_score_mean: float = 0.0
    url_signals: List[Dict[str, Any]] = field(default_factory=list)

    # Phase 6 Tactic Detection outputs
    detected_tactics: List[str] = field(default_factory=list)
    tactic_evidence: List[Dict[str, Any]] = field(default_factory=list)

    # Phase 7 Semantic Similarity & Novelty outputs
    top1_similarity: Optional[float] = None
    top_k_similarities: List[float] = field(default_factory=list)
    semantic_novelty_score: Optional[float] = None
    semantic_status: Optional[str] = None  # "similar_to_known", "moderately_novel", "potentially_novel"
    known_pattern_status: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        """Serializes assessment input to dictionary."""
        return asdict(self)


@dataclass
class CaseAssessmentResult:
    """Unified container for complete case assessment, evidence, explanation, and audit."""

    sample_id: Optional[str]
    assessment: AssessmentSummary
    signals: Dict[str, Any]
    evidence: List[EvidenceItem] = field(default_factory=list)
    supporting_signals: List[str] = field(default_factory=list)
    contradicting_signals: List[str] = field(default_factory=list)
    explanation: ExplanationObject = field(
        default_factory=lambda: ExplanationObject(summary="")
    )
    audit: AuditObject = field(default_factory=AuditObject)

    def to_dict(self) -> Dict[str, Any]:
        """Serializes complete case assessment to standardized JSON dictionary."""
        return {
            "sample_id": self.sample_id,
            "assessment": self.assessment.to_dict(),
            "signals": self.signals,
            "evidence": [e.to_dict() for e in self.evidence],
            "supporting_signals": self.supporting_signals,
            "contradicting_signals": self.contradicting_signals,
            "explanation": self.explanation.to_dict(),
            "audit": self.audit.to_dict(),
        }
