"""Deterministic offline mock explanation model for ScamShield AI Phase 10.

Guarantees:
1. 100% Offline: Zero external network or API calls.
2. Perfect Grounding: Uses strictly supplied deterministic findings and retrieved chunks.
3. Decision Immutability: Preserves Phase 8 status without deviation.
4. Valid Citations: Emits verifiable [CASE:...] and [KB:...] citation tags.
5. Default Test Provider: Enables complete automated test suite execution without API keys.
"""

from typing import Any, Dict, List

from .base import BaseExplanationModel
from .schemas import (
    ExplanationRequest,
    ExplanationResponse,
    KnowledgeContextItem,
    ObservedEvidenceItem,
    TacticExplanationItem,
)


class MockExplanationModel(BaseExplanationModel):
    """Deterministic, rule-guided mock provider synthesizing grounded explanations."""

    @property
    def provider_name(self) -> str:
        return "mock"

    def generate_explanation(self, request: ExplanationRequest) -> ExplanationResponse:
        """Synthesizes a structured explanation strictly from the supplied request context."""
        det = request.deterministic_result
        status = det.get("status", "insufficient_evidence")
        ev_level = det.get("evidence_level", "low")
        consistency = det.get("signal_consistency", "insufficient")
        tactics = request.tactics or []

        # 1. Decision Summary
        if status == "likely_scam":
            tactics_str = ", ".join(tactics) if tactics else "multiple behavioral indicators"
            summary = (
                f"The message is assessed as likely scam based on {ev_level} evidence "
                f"exhibiting {tactics_str}. Upstream signals show {consistency}."
            )
            decision_context = (
                f"The deterministic evaluation identified characteristic scam patterns "
                f"including {len(request.evidence)} discrete evidence indicators and "
                f"{len(request.url_findings)} URL risk signals."
            )
        elif status == "likely_non_scam":
            summary = (
                "The communication appears consistent with legitimate or benign interaction. "
                "No deceptive urgency, credential harvesting, or malicious URL indicators were observed."
            )
            decision_context = (
                "Upstream classifiers and heuristic modules found no structural scam tactics or high-risk "
                "destination links, leading to a likely non-scam assessment."
            )
        elif status == "mixed_signals":
            summary = (
                "The analysis detected conflicting indicators across detection components. "
                "While some features triggered caution, the overall evidence is not mutually corroborating."
            )
            decision_context = (
                f"Contradictions exist across upstream modules ({len(request.contradictions)} noted). "
                "The system avoids false accusations by holding a mixed-signals status."
            )
        else:
            summary = (
                "Available evidence is insufficient to establish a definitive scam or legitimate status. "
                "Exercise normal caution before responding."
            )
            decision_context = (
                "The input content lacks distinctive behavioral tactics, destination links, or recognized patterns."
            )

        # 2. Observed Evidence Items
        observed_items: List[Dict[str, Any]] = []
        for ev in request.evidence[:5]:
            c_id = ev.get("citation_id", f"[CASE:{ev.get('evidence_id', 'unknown')}]")
            reason = ev.get("reason", ev.get("name", "Observed indicator"))
            observed_items.append({
                "evidence": reason,
                "source": "case",
                "citation": c_id,
            })

        # 3. Tactic Explanations
        tactic_items: List[Dict[str, Any]] = []
        for t in tactics:
            # Find evidence supporting this tactic
            matching_ev = [
                e for e in request.evidence if e.get("name", "").lower() == t.lower() or e.get("type") == "tactic"
            ]
            if matching_ev:
                t_reason = matching_ev[0].get("reason", f"Detected behavioral pattern matching {t}")
            else:
                t_reason = f"Identified linguistic and contextual signals corresponding to {t}."
            tactic_items.append({
                "tactic": t,
                "explanation": t_reason,
            })

        # 4. Knowledge Context Items
        knowledge_items: List[Dict[str, Any]] = []
        for kb in request.retrieved_knowledge[:3]:
            doc_id = kb.get("document_id", "")
            chunk_id = kb.get("chunk_id", "")
            c_id = kb.get("citation_id", f"[KB:{doc_id}:{chunk_id}]")
            title = kb.get("title", "")
            text = kb.get("text", "")
            first_sentence = text.split("\n")[0].strip() if text else title
            knowledge_items.append({
                "claim": f"{title}: {first_sentence}",
                "source_document": doc_id,
                "chunk_id": chunk_id,
                "citation": c_id,
            })

        # 5. Uncertainties & Caveats
        uncertainties: List[str] = []
        for c in request.contradictions:
            uncertainties.append(f"Contradiction note: {c}")

        if request.visual_findings:
            uncertainties.append(
                "Visual observations (such as QR codes or layout banners) are contextual layout features "
                "and do not independently establish fraudulent intent."
            )

        sem = request.semantic_findings
        if sem.get("semantic_status") == "potentially_novel":
            uncertainties.append(
                "This message exhibits low similarity to known benchmark clusters. Novelty indicates "
                "limited comparison precedent, not verified fraud."
            )

        if not uncertainties and status in ["mixed_signals", "insufficient_evidence"]:
            uncertainties.append("Signal strength is below the threshold required for definitive categorization.")

        # 6. Recommended Action
        if status == "likely_scam":
            rec_action = (
                "Do not interact with embedded hyperlinks or disclose confidential authentication codes (OTPs, PINs). "
                "If the message references a bank or utility, verify account status through official standalone apps "
                "or telephone numbers obtained from independent billing statements."
            )
        elif status == "mixed_signals":
            rec_action = (
                "Exercise heightened vigilance. Verify the sender's identity through an independent, verified contact "
                "channel before clicking links or acting on requests."
            )
        else:
            rec_action = (
                "Maintain standard digital security hygiene. Verify unknown sender addresses and avoid sharing "
                "passwords or sensitive information."
            )

        # 7. Confidence Statement
        conf_stmt = (
            f"Assessment is grounded in {ev_level} deterministic evidence with {consistency} "
            f"across {len(request.evidence)} discrete case observations."
        )

        return ExplanationResponse(
            summary=summary,
            decision_context=decision_context,
            observed_evidence=observed_items,
            tactic_explanations=tactic_items,
            knowledge_context=knowledge_items,
            uncertainties=uncertainties,
            recommended_action=rec_action,
            confidence_statement=conf_stmt,
        )
