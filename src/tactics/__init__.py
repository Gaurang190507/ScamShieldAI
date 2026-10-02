"""ScamShield AI — Phase 6 Scam Tactic Detection and Evidence Extraction Module.

Provides deterministic, offline, and explainable behavioral tactic detection
grounded in verifiable evidence spans directly anchored to the original message text.
"""

from .evidence import EvidenceEngine
from .schemas import DetectedTactic, EvidenceSpan, TacticResult
from .tactic_detector import TacticDetector
from .tactic_rules import TACTIC_SEVERITY, TacticRule, build_tactic_rules

__all__ = [
    "DetectedTactic",
    "EvidenceEngine",
    "EvidenceSpan",
    "TACTIC_SEVERITY",
    "TacticDetector",
    "TacticResult",
    "build_tactic_rules",
]
