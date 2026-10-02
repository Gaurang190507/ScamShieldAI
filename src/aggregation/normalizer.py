"""Signal normalizer and evidence extractor for ScamShield AI Phase 8.

Converts upstream module outputs into standardized CaseAssessmentInput and
creates granular, traceable EvidenceItem instances anchored to verbatim spans,
URL signals, and classification probabilities.
"""

from typing import Any, Dict, List, Optional, Tuple
from .schemas import CaseAssessmentInput, EvidenceItem


class SignalNormalizer:
    """Normalizes raw outputs from Phases 3, 4, 6, and 7 into structured evidence."""

    @staticmethod
    def extract_evidence_items(
        case_input: CaseAssessmentInput,
    ) -> Tuple[List[EvidenceItem], List[str], List[str]]:
        """Extracts atomic evidence items, supporting signals, and contradicting signals.

        Args:
            case_input: Normalized CaseAssessmentInput.

        Returns:
            Tuple of:
            - List of EvidenceItem instances.
            - List of supporting signal names (supporting scam hypothesis).
            - List of contradicting signal names (contradicting scam hypothesis).
        """
        evidence: List[EvidenceItem] = []
        supporting_signals: List[str] = []
        contradicting_signals: List[str] = []

        counter = 1

        # ---------------------------------------------------------------------
        # 1. Phase 3 Text Classifier Evidence
        # ---------------------------------------------------------------------
        p = case_input.text_classifier_probability
        thresh = case_input.text_classifier_threshold or 0.30

        if p is not None:
            if p >= thresh:
                evidence.append(
                    EvidenceItem(
                        evidence_id=f"ev_{counter:03d}",
                        source="phase3_classifier",
                        type="classification",
                        name="scam_probability",
                        value=round(p, 4),
                        strength="supporting",
                        reason=(
                            f"Text classifier score ({p:.4f}) meets or exceeds the "
                            f"benchmark decision threshold ({thresh:.2f})."
                        ),
                    )
                )
                supporting_signals.append("text_classifier_scam")
            else:
                evidence.append(
                    EvidenceItem(
                        evidence_id=f"ev_{counter:03d}",
                        source="phase3_classifier",
                        type="classification",
                        name="scam_probability",
                        value=round(p, 4),
                        strength="contradicting",
                        reason=(
                            f"Text classifier score ({p:.4f}) is below the "
                            f"benchmark decision threshold ({thresh:.2f})."
                        ),
                    )
                )
                contradicting_signals.append("text_classifier_non_scam")
            counter += 1

        # ---------------------------------------------------------------------
        # 2. Phase 4 URL Structural Analysis Evidence
        # ---------------------------------------------------------------------
        url_risk = case_input.url_risk_score_max
        if case_input.url_count > 0:
            if url_risk >= 0.50:
                supporting_signals.append("url_structural_risk_high")
            elif url_risk <= 0.20:
                contradicting_signals.append("url_structural_risk_low")

            # Extract specific URL heuristic signals
            for sig in case_input.url_signals:
                sig_name = (
                    sig.get("name")
                    or sig.get("signal")
                    or sig.get("signal_name", "url_heuristic")
                )
                sig_url = sig.get("url") or sig.get("matched_url")
                sig_reason = sig.get("reason") or sig.get("description", "URL structural anomaly detected.")
                sig_score = (
                    sig.get("score")
                    if sig.get("score") is not None
                    else (sig.get("weight") or sig.get("risk_score", 0.0))
                )

                evidence.append(
                    EvidenceItem(
                        evidence_id=f"ev_{counter:03d}",
                        source="phase4_url",
                        type="url_signal",
                        name=sig_name,
                        value=sig_score,
                        url=sig_url,
                        strength="supporting" if (sig_score or 0.0) >= 0.40 else "weak",
                        reason=sig_reason,
                    )
                )
                counter += 1

        # ---------------------------------------------------------------------
        # 3. Phase 6 Tactic Detection Evidence
        # ---------------------------------------------------------------------
        if case_input.detected_tactics:
            for t_item in case_input.tactic_evidence:
                t_name = t_item.get("tactic", "unknown_tactic")
                t_text = t_item.get("matched_text") or t_item.get("text")
                t_start = t_item.get("start")
                t_end = t_item.get("end")
                t_sev = t_item.get("severity", "medium")
                t_reason = t_item.get("reason", f"Detected behavioral tactic: {t_name}")

                evidence.append(
                    EvidenceItem(
                        evidence_id=f"ev_{counter:03d}",
                        source="phase6_tactic",
                        type="tactic",
                        name=t_name,
                        text=t_text,
                        start=t_start,
                        end=t_end,
                        strength="supporting" if t_sev in ("high", "medium") else "weak",
                        reason=t_reason,
                    )
                )
                counter += 1

            # High or medium tactics count as supporting signal
            supporting_signals.append(f"tactics_detected_{len(case_input.detected_tactics)}")
        else:
            contradicting_signals.append("zero_tactics_detected")

        # ---------------------------------------------------------------------
        # 4. Phase 7 Semantic Similarity & Novelty Evidence
        # ---------------------------------------------------------------------
        top1 = case_input.top1_similarity
        nov = case_input.semantic_novelty_score
        status = case_input.semantic_status

        if top1 is not None:
            evidence.append(
                EvidenceItem(
                    evidence_id=f"ev_{counter:03d}",
                    source="phase7_similarity",
                    type="semantic_context",
                    name="top1_similarity",
                    value=round(top1, 4),
                    strength="contextual",
                    reason=(
                        f"Nearest reference corpus example exhibits cosine similarity of {top1:.4f} "
                        f"(status: {status or 'unknown'})."
                    ),
                )
            )
            counter += 1

        if nov is not None:
            evidence.append(
                EvidenceItem(
                    evidence_id=f"ev_{counter:03d}",
                    source="phase7_similarity",
                    type="semantic_context",
                    name="semantic_novelty_score",
                    value=round(nov, 4),
                    strength="contextual",
                    reason=(
                        f"Relative semantic novelty score is {nov:.4f} compared to the "
                        "known reference training corpus. Note: Novelty reflects vector distance, not scam status."
                    ),
                )
            )
            counter += 1

        return evidence, supporting_signals, contradicting_signals
