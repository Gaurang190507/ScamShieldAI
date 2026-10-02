"""Risk scoring engine communicating uncertainty across tactical indicators.

Follows the core principle: Never claim an item is definitely a scam.
Communicates risk with explicit uncertainty levels:
- High risk
- Medium risk
- Low risk
- Suspicious
- Potentially emerging pattern
- Insufficient evidence
"""

from enum import Enum
from typing import Dict, List, Any


class RiskLevel(str, Enum):
    HIGH_RISK = "High risk"
    MEDIUM_RISK = "Medium risk"
    LOW_RISK = "Low risk"
    SUSPICIOUS = "Suspicious"
    POTENTIALLY_EMERGING = "Potentially emerging pattern"
    INSUFFICIENT_EVIDENCE = "Insufficient evidence"


class RiskEngine:
    """Aggregates behavioral indicators, rules, and model predictions into calibrated risk assessments."""

    def __init__(self):
        pass

    def evaluate(
        self,
        detected_tactics: Dict[str, List[str]],
        ml_scores: Dict[str, float] = None,
        url_flags: List[str] = None,
        novelty_flag: bool = False,
    ) -> Dict[str, Any]:
        """Synthesizes tactical evidence into an uncertainty-aware assessment.

        Args:
            detected_tactics: Heuristic tactic indicators (urgency, credentials, etc.)
            ml_scores: Model confidence outputs for indicators.
            url_flags: Flags raised from URL scanning.
            novelty_flag: Whether unseen anomalous behavioral structures were detected.

        Returns:
            Dict containing risk_level, confidence_assessment, and reasoning breakdown.
        """
        ml_scores = ml_scores or {}
        url_flags = url_flags or []

        # Placeholder rule evaluation logic
        tactic_count = len(detected_tactics)
        has_critical_indicators = any(
            t in detected_tactics for t in ["otp_or_credentials", "payment_demands"]
        )

        if not detected_tactics and not url_flags:
            risk = RiskLevel.INSUFFICIENT_EVIDENCE
            explanation = "No distinctive scam tactics or high-risk indicators were detected in the input."
        elif novelty_flag and tactic_count <= 1:
            risk = RiskLevel.POTENTIALLY_EMERGING
            explanation = "Content exhibits unusual structural anomalies that may represent an emerging tactic."
        elif has_critical_indicators and tactic_count >= 2:
            risk = RiskLevel.HIGH_RISK
            explanation = "Multiple high-risk tactics observed in combination (e.g. credential/payment pressure)."
        elif tactic_count >= 1 or len(url_flags) >= 1:
            risk = RiskLevel.SUSPICIOUS
            explanation = "Individual suspicious indicators detected, but insufficient tactical convergence for high risk."
        else:
            risk = RiskLevel.LOW_RISK
            explanation = "Indicators suggest low probability of deceptive tactics."

        return {
            "risk_level": risk.value,
            "detected_tactics": detected_tactics,
            "url_flags": url_flags,
            "explanation": explanation,
            "evidence_count": tactic_count + len(url_flags),
        }
