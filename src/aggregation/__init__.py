"""ScamShield AI — Phase 8: Multi-Signal Risk Aggregation & Forensic Audit.

Provides deterministic, auditable multi-signal risk aggregation combining:
- Phase 3: Text scam/non-scam classification
- Phase 4: Passive offline URL structural heuristics
- Phase 6: Scam tactic detection & grounded evidence spans
- Phase 7: Semantic similarity & relative novelty detection
"""

from .schemas import (
    EvidenceItem,
    AssessmentSummary,
    ExplanationObject,
    AuditObject,
    CaseAssessmentInput,
    CaseAssessmentResult,
)
from .normalizer import SignalNormalizer
from .aggregator import RiskAggregator
from .pipeline import CaseAssessmentPipeline

__all__ = [
    "EvidenceItem",
    "AssessmentSummary",
    "ExplanationObject",
    "AuditObject",
    "CaseAssessmentInput",
    "CaseAssessmentResult",
    "SignalNormalizer",
    "RiskAggregator",
    "CaseAssessmentPipeline",
]
