"""Rule-based multi-signal risk aggregator and forensic decision engine for ScamShield AI.

Synthesizes outputs from Phases 3, 4, 6, and 7:
- Preserves explicit distinctions between classification, tactics, URL heuristics, and novelty.
- Handles contradictory signals transparently without arbitrary pseudo-probabilities.
- Emits deterministic case status, evidence level, signal consistency, and audit trails.
"""

from typing import Any, Dict, List, Optional
from .normalizer import SignalNormalizer
from .schemas import (
    AssessmentSummary,
    AuditObject,
    CaseAssessmentInput,
    CaseAssessmentResult,
    EvidenceItem,
    ExplanationObject,
)


class RiskAggregator:
    """Transparent, deterministic rule-based aggregator for multi-signal fraud evaluation."""

    # High-severity behavioral tactics indicating direct exploitation
    HIGH_SEVERITY_TACTICS = {
        "remote_access_request",
        "otp_request",
        "credential_request",
        "payment_request",
        "secrecy_request",
        "account_suspension",
    }

    def aggregate(self, case_input: CaseAssessmentInput) -> CaseAssessmentResult:
        """Evaluates normalized case signals and produces auditable assessment.

        Args:
            case_input: Normalized CaseAssessmentInput.

        Returns:
            Structured CaseAssessmentResult.
        """
        # 1. Normalize and extract atomic evidence items
        evidence, supporting_sigs, contradicting_sigs = (
            SignalNormalizer.extract_evidence_items(case_input)
        )

        text = case_input.text or ""
        p = case_input.text_classifier_probability
        thresh = case_input.text_classifier_threshold or 0.30
        url_count = case_input.url_count
        url_risk_max = case_input.url_risk_score_max
        tactics = set(case_input.detected_tactics)
        tactic_count = len(tactics)
        high_sev_tactics = tactics.intersection(self.HIGH_SEVERITY_TACTICS)
        high_sev_count = len(high_sev_tactics)

        top1_sim = case_input.top1_similarity
        novelty_score = case_input.semantic_novelty_score
        semantic_status = case_input.semantic_status or "unknown"

        # Signal state variables
        classifier_is_scam = p is not None and p >= thresh
        classifier_is_non_scam = p is not None and p < thresh
        url_is_high_risk = url_count > 0 and url_risk_max >= 0.50
        url_is_low_risk = url_count > 0 and url_risk_max <= 0.20
        url_is_clean_or_absent = url_count == 0 or url_is_low_risk

        # ---------------------------------------------------------------------
        # 2. Deterministic Case Status & Decision Rules
        # ---------------------------------------------------------------------
        status = "insufficient_evidence"
        decision_rule = "rule_default_insufficient"
        evidence_level = "low"
        consistency = "insufficient"

        if not text.strip():
            status = "insufficient_evidence"
            decision_rule = "rule_empty_content"
            evidence_level = "low"
            consistency = "insufficient"

        # Rule Group 1: Strong Multi-Signal Scam
        elif classifier_is_scam and (tactic_count >= 1 or url_is_high_risk):
            status = "likely_scam"
            if high_sev_count >= 1 or (tactic_count >= 2 and url_is_high_risk):
                decision_rule = "rule_strong_scam_classifier_and_severe_tactics"
                evidence_level = "high"
                consistency = "strong_agreement" if url_count == 0 or url_is_high_risk else "moderate_agreement"
            else:
                decision_rule = "rule_scam_classifier_and_tactics"
                evidence_level = "moderate"
                consistency = "moderate_agreement"

        # Rule Group 2: Severe Behavioral Exploitation Override (Critical Tactics)
        elif high_sev_count >= 2 or ("otp_request" in tactics) or ("credential_request" in tactics):
            status = "likely_scam"
            decision_rule = "rule_critical_tactics_exploitation_override"
            evidence_level = "high"
            consistency = "moderate_agreement" if classifier_is_scam else "mixed"

        # Rule Group 3: Strong Unanimous Legitimate / Non-Scam
        elif classifier_is_non_scam and tactic_count == 0 and url_is_clean_or_absent:
            status = "likely_non_scam"
            decision_rule = "rule_clean_non_scam_unanimous"
            evidence_level = "low"
            consistency = "strong_agreement"

        # Rule Group 4: Contradictory Signals (Disagreements)
        elif classifier_is_scam and tactic_count == 0 and url_is_clean_or_absent:
            # Model flagged text, but zero behavioral tactics and clean/no URL
            status = "mixed_signals"
            decision_rule = "rule_contradiction_classifier_scam_clean_behavior"
            evidence_level = "moderate"
            consistency = "mixed"

        elif classifier_is_non_scam and url_is_high_risk:
            # Benign text but structural URL threat
            status = "mixed_signals"
            decision_rule = "rule_contradiction_url_threat_low_text_score"
            evidence_level = "moderate"
            consistency = "mixed"

        elif classifier_is_non_scam and tactic_count >= 1:
            # Classifier is below threshold but isolated tactics detected
            status = "mixed_signals"
            decision_rule = "rule_contradiction_tactics_present_low_classifier"
            evidence_level = "moderate"
            consistency = "mixed"

        else:
            # Edge cases / ambiguous combinations
            status = "mixed_signals"
            decision_rule = "rule_ambiguous_signal_combination"
            evidence_level = "moderate"
            consistency = "mixed"

        # ---------------------------------------------------------------------
        # 3. Deterministic Explanation Synthesis
        # ---------------------------------------------------------------------
        reasons: List[str] = []
        cautions: List[str] = []

        if classifier_is_scam:
            reasons.append(
                f"Statistical text classifier indicates scam pattern (estimated score: {p:.4f}, threshold: {thresh:.2f})."
            )
        elif classifier_is_non_scam:
            reasons.append(
                f"Statistical text classifier indicates non-scam pattern (estimated score: {p:.4f}, threshold: {thresh:.2f})."
            )

        if tactic_count > 0:
            tactic_names_str = ", ".join(sorted(list(tactics)))
            reasons.append(
                f"Detected {tactic_count} behavioral tactic(s): {tactic_names_str}."
            )
            if high_sev_count > 0:
                reasons.append(
                    f"Contains {high_sev_count} high-severity exploitation tactic(s) ({', '.join(sorted(list(high_sev_tactics)))})."
                )
        else:
            reasons.append("Zero manipulative behavioral tactics detected in message text.")

        if url_count > 0:
            if url_is_high_risk:
                reasons.append(
                    f"Passive URL analysis flagged structural risk (max heuristic score: {url_risk_max:.2f})."
                )
            else:
                reasons.append(
                    f"Embedded URL(s) exhibit low structural risk (max score: {url_risk_max:.2f})."
                )

        # Contextual Semantic & Novelty Findings (Never called scam)
        if top1_sim is not None:
            reasons.append(
                f"Semantic proximity to training reference corpus: top-1 similarity {top1_sim:.4f} ({semantic_status})."
            )

        # Contradiction / Caution Notes
        if status == "mixed_signals":
            cautions.append(
                "Upstream signals actively disagree. Manual investigation or corroborating evidence is recommended before acting."
            )
            if classifier_is_scam and tactic_count == 0:
                cautions.append(
                    "The text classifier assigned a high scam score, but no explicit deceptive tactics or URL anomalies were confirmed."
                )
            elif classifier_is_non_scam and url_is_high_risk:
                cautions.append(
                    "The text classifier assigned a low scam score, but the embedded URL exhibits suspicious structural characteristics."
                )

        if novelty_score is not None and novelty_score >= 0.50:
            cautions.append(
                f"High semantic novelty score ({novelty_score:.4f}): message diverges from the reference training corpus. "
                "Novelty indicates uncataloged vocabulary or pattern structure, not definitive fraud."
            )

        # Summary text
        if status == "likely_scam":
            summary = (
                f"Assessment: LIKELY SCAM ({evidence_level.upper()} evidence level). Multiple corroborating signals "
                "indicate deceptive or manipulative intent."
            )
        elif status == "likely_non_scam":
            summary = (
                "Assessment: LIKELY NON-SCAM. The message does not exhibit manipulative tactics, "
                "the text classifier is below threshold, and no URL structural threats were identified."
            )
        elif status == "mixed_signals":
            summary = (
                "Assessment: MIXED SIGNALS. Independent signals contradict each other. "
                "Requires careful inspection of specific evidence findings."
            )
        else:
            summary = "Assessment: INSUFFICIENT EVIDENCE. Content lacks sufficient signal for conclusive evaluation."

        explanation = ExplanationObject(
            summary=summary,
            reasons=reasons,
            cautions=cautions,
        )

        # ---------------------------------------------------------------------
        # 4. Forensic Audit Trail Object
        # ---------------------------------------------------------------------
        audit = AuditObject(
            phase3_used=p is not None,
            phase4_used=True,
            phase5_used=False,  # Phase 5 is excluded from runtime inference to avoid double-counting
            phase6_used=True,
            phase7_used=top1_sim is not None,
            network_access=False,
            external_lookup=False,
            final_decision_rule=decision_rule,
            evidence_count=len(evidence),
            contradiction_count=len(contradicting_sigs),
        )

        # Structured signal dictionary
        signals_dict: Dict[str, Any] = {
            "text_classifier": {
                "probability": p,
                "threshold": thresh,
                "predicted_label": case_input.text_classifier_label,
            },
            "url_analysis": {
                "url_count": url_count,
                "max_risk_score": url_risk_max,
                "signals_count": len(case_input.url_signals),
            },
            "tactics": {
                "count": tactic_count,
                "detected": sorted(list(tactics)),
                "high_severity_count": high_sev_count,
            },
            "semantic_similarity": {
                "top1_similarity": top1_sim,
                "novelty_score": novelty_score,
                "semantic_status": semantic_status,
            },
        }

        return CaseAssessmentResult(
            sample_id=case_input.sample_id,
            assessment=AssessmentSummary(
                status=status,
                evidence_level=evidence_level,
                signal_consistency=consistency,
            ),
            signals=signals_dict,
            evidence=evidence,
            supporting_signals=supporting_sigs,
            contradicting_signals=contradicting_sigs,
            explanation=explanation,
            audit=audit,
        )
