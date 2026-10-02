"""Canonical data schemas for ScamShield AI Phase 10 Explanation Layer.

Defines structured interfaces for:
- ExplanationRequest: Standardized context passed to the explanation model.
- ExplanationResponse: Validated structured explanation produced by the LLM.
- GroundingValidationResult: Forensic check of citations, evidence, and decision immutability.
- Phase10InvestigationReport: Final end-to-end grounded investigation report.
"""

from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional


@dataclass
class ExplanationRequest:
    """Standardized input context fed into the explanation provider."""

    case_id: str
    deterministic_result: Dict[str, Any]  # status, evidence_level, signal_consistency, classification
    tactics: List[str] = field(default_factory=list)
    url_findings: List[Dict[str, Any]] = field(default_factory=list)
    semantic_findings: Dict[str, Any] = field(default_factory=dict)
    visual_findings: List[Dict[str, Any]] = field(default_factory=list)
    contradictions: List[str] = field(default_factory=list)
    evidence: List[Dict[str, Any]] = field(default_factory=list)  # Atomic evidence items with citation_id
    retrieved_knowledge: List[Dict[str, Any]] = field(default_factory=list)  # Retrieved chunks with citation_id
    raw_text: Optional[str] = None  # Delimited untrusted user content

    def to_dict(self) -> Dict[str, Any]:
        """Serializes explanation request to dictionary."""
        return asdict(self)


@dataclass
class ObservedEvidenceItem:
    """Atomic observed evidence item with source citation."""

    evidence: str
    source: str = "case"
    citation: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class TacticExplanationItem:
    """Explanation of a specific detected tactic."""

    tactic: str
    explanation: str

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class KnowledgeContextItem:
    """Factual claim grounded in retrieved reference knowledge."""

    claim: str
    source_document: str
    chunk_id: str
    citation: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class ExplanationResponse:
    """Structured, validated response returned by the explanation model."""

    summary: str
    decision_context: str
    observed_evidence: List[Dict[str, Any]] = field(default_factory=list)
    tactic_explanations: List[Dict[str, Any]] = field(default_factory=list)
    knowledge_context: List[Dict[str, Any]] = field(default_factory=list)
    uncertainties: List[str] = field(default_factory=list)
    recommended_action: str = ""
    confidence_statement: str = ""

    def to_dict(self) -> Dict[str, Any]:
        """Serializes explanation response to dictionary."""
        return asdict(self)


@dataclass
class GroundingValidationResult:
    """Forensic verification certifying explanation grounding and decision immutability."""

    is_grounded: bool
    status: str  # "grounded", "needs_review", "rejected"
    evidence_check_passed: bool
    citation_check_passed: bool
    tactic_check_passed: bool
    decision_check_passed: bool
    unsupported_claims: List[str] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        """Serializes grounding validation result to dictionary."""
        return asdict(self)


@dataclass
class Phase10InvestigationReport:
    """Unified final investigation report combining deterministic verdict and grounded explanation."""

    case_id: str
    deterministic_assessment: Dict[str, Any]
    explanation: Dict[str, Any]
    grounding: Dict[str, Any]
    audit: Dict[str, Any]

    def to_dict(self) -> Dict[str, Any]:
        """Serializes investigation report to standardized JSON dictionary."""
        return {
            "case_id": self.case_id,
            "deterministic_assessment": self.deterministic_assessment,
            "explanation": self.explanation,
            "grounding": self.grounding,
            "audit": self.audit,
        }
