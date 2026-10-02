"""Emerging and Novel Scam Pattern Analyzer for ScamShield AI Phase 17 (Fix #6).

Evaluates messages exhibiting high semantic novelty against behavioral exploitation signals
without keyword memorization or overfitting to specific training narratives.

Core Invariants:
- Preserves explicit distinction: KNOWN PATTERN vs. UNKNOWN/EMERGING PATTERN vs. INSUFFICIENT EVIDENCE.
- Does NOT hardcode specific story themes (e.g. green hydrogen, digital arrest scripts).
- Combines semantic distance (Phase 7) with behavioral tactics (Phase 6/17) and URL heuristics (Phase 4).
- Distinguishes novel benign communications from novel hostile fraud campaigns.
"""

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set


# High-severity behavioral signals indicating exploitation even in novel narratives
EXPLOITATION_TACTICS: Set[str] = {
    "coercive_authority",
    "indirect_payment_demand",
    "isolation_enforcement",
    "remote_access_request",
    "otp_request",
    "credential_request",
    "payment_request",
    "account_suspension",
    "threat",
}

SECONDARY_TACTICS: Set[str] = {
    "conversational_urgency",
    "urgency",
    "reward_promise",
    "impersonation",
    "toll_free_bait",
}


@dataclass
class EmergingPatternResult:
    """Evaluation result for novel/unknown threat analysis."""

    pattern_type: str  # "known_pattern", "emerging_threat", "novel_ambiguous", "novel_benign", "insufficient_evidence"
    is_emerging_threat: bool
    novelty_score: Optional[float]
    top1_similarity: Optional[float]
    corroborating_tactics: List[str]
    high_severity_tactic_count: int
    url_risk_max: float
    recommended_verdict: Optional[str]  # "likely_scam", "mixed_signals", "likely_non_scam", None
    rationale: str

    def to_dict(self) -> Dict[str, Any]:
        return {
            "pattern_type": self.pattern_type,
            "is_emerging_threat": self.is_emerging_threat,
            "novelty_score": self.novelty_score,
            "top1_similarity": self.top1_similarity,
            "corroborating_tactics": self.corroborating_tactics,
            "high_severity_tactic_count": self.high_severity_tactic_count,
            "url_risk_max": self.url_risk_max,
            "recommended_verdict": self.recommended_verdict,
            "rationale": self.rationale,
        }


class EmergingPatternAnalyzer:
    """Interprets multi-signal evidence for novel and out-of-distribution communications."""

    def __init__(
        self,
        novelty_threshold: float = 0.50,
        low_similarity_threshold: float = 0.45,
    ):
        """Initializes analyzer with calibrated semantic thresholds.

        Args:
            novelty_threshold: Semantic distance score at or above which an input is novel.
            low_similarity_threshold: Reference similarity at or below which an input is distant.
        """
        self.novelty_threshold = novelty_threshold
        self.low_similarity_threshold = low_similarity_threshold

    def analyze(
        self,
        text: str,
        detected_tactics: List[str],
        novelty_score: Optional[float] = None,
        top1_similarity: Optional[float] = None,
        url_risk_max: float = 0.0,
        url_count: int = 0,
        classifier_prob: Optional[float] = None,
        classifier_thresh: float = 0.30,
    ) -> EmergingPatternResult:
        """Analyzes an input for emerging/novel scam characteristics.

        Args:
            text: Message text.
            detected_tactics: All detected tactic names (Phase 6 + Phase 17).
            novelty_score: Semantic novelty score from Phase 7.
            top1_similarity: Top-1 similarity to reference corpus from Phase 7.
            url_risk_max: Maximum heuristic risk score across extracted URLs.
            url_count: Number of URLs extracted.
            classifier_prob: Statistical classifier probability from Phase 3/13.
            classifier_thresh: Decision threshold for statistical classifier.

        Returns:
            EmergingPatternResult containing pattern taxonomy and rationale.
        """
        if not isinstance(text, str) or not text.strip():
            return EmergingPatternResult(
                pattern_type="insufficient_evidence",
                is_emerging_threat=False,
                novelty_score=novelty_score,
                top1_similarity=top1_similarity,
                corroborating_tactics=[],
                high_severity_tactic_count=0,
                url_risk_max=url_risk_max,
                recommended_verdict="insufficient_evidence",
                rationale="Empty or whitespace-only input lacks sufficient content for novelty interpretation.",
            )

        tactics_set = set(detected_tactics)
        high_sev = [t for t in detected_tactics if t in EXPLOITATION_TACTICS]
        sec_tactics = [t for t in detected_tactics if t in SECONDARY_TACTICS]
        high_sev_count = len(high_sev)

        # Determine if input is semantically novel relative to reference corpus
        is_novel = False
        if novelty_score is not None and novelty_score >= self.novelty_threshold:
            is_novel = True
        elif top1_similarity is not None and top1_similarity <= self.low_similarity_threshold:
            is_novel = True

        # Case 1: Known / Familiar pattern
        if not is_novel:
            return EmergingPatternResult(
                pattern_type="known_pattern",
                is_emerging_threat=False,
                novelty_score=novelty_score,
                top1_similarity=top1_similarity,
                corroborating_tactics=detected_tactics,
                high_severity_tactic_count=high_sev_count,
                url_risk_max=url_risk_max,
                recommended_verdict=None,  # Defer to standard Phase 8 aggregator
                rationale="Content aligns with documented reference corpus patterns.",
            )

        # Case 2: Novel Storyline with Strong Behavioral Exploitation (Emerging Threat)
        # Meets novelty threshold AND contains either high-severity tactics, multiple tactics, or malicious URL
        has_strong_tactics = high_sev_count >= 1 or len(tactics_set) >= 2
        has_malicious_url = url_count > 0 and url_risk_max >= 0.50

        if has_strong_tactics or has_malicious_url:
            rationale_parts = [
                f"High semantic novelty ({novelty_score:.4f} score)" if novelty_score else "Semantic divergence from reference corpus",
                f"corroborated by {len(tactics_set)} behavioral tactic(s): {', '.join(sorted(list(tactics_set)))}" if tactics_set else "",
                f"and elevated URL risk ({url_risk_max:.2f})" if has_malicious_url else "",
            ]
            full_rationale = " ".join([p for p in rationale_parts if p]).strip() + ". Classified as an emerging, novel fraud campaign."

            return EmergingPatternResult(
                pattern_type="emerging_threat",
                is_emerging_threat=True,
                novelty_score=novelty_score,
                top1_similarity=top1_similarity,
                corroborating_tactics=sorted(list(tactics_set)),
                high_severity_tactic_count=high_sev_count,
                url_risk_max=url_risk_max,
                recommended_verdict="likely_scam",
                rationale=full_rationale,
            )

        # Case 3: Novel Storyline with Weak/Isolated Tactics (Ambiguous)
        if len(tactics_set) == 1:
            single_tactic = list(tactics_set)[0]
            return EmergingPatternResult(
                pattern_type="novel_ambiguous",
                is_emerging_threat=False,
                novelty_score=novelty_score,
                top1_similarity=top1_similarity,
                corroborating_tactics=[single_tactic],
                high_severity_tactic_count=high_sev_count,
                url_risk_max=url_risk_max,
                recommended_verdict="mixed_signals",
                rationale=(
                    f"Message exhibits high semantic novelty with an isolated weak tactic ('{single_tactic}') "
                    "without corroborating exploitation signals. Requires human review."
                ),
            )

        # Case 4: Novel Storyline with Zero Exploitation Tactics and Safe URLs (Novel Benign)
        return EmergingPatternResult(
            pattern_type="novel_benign",
            is_emerging_threat=False,
            novelty_score=novelty_score,
            top1_similarity=top1_similarity,
            corroborating_tactics=[],
            high_severity_tactic_count=0,
            url_risk_max=url_risk_max,
            recommended_verdict="likely_non_scam",
            rationale=(
                "Novel vocabulary and narrative structure with zero manipulative tactics, "
                "no credential/payment demands, and no malicious URLs. Classified as benign novel content."
            ),
        )
