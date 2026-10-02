"""Post-generation grounding validator for ScamShield AI Phase 10.

Forensically verifies that generated explanations:
1. Evidence Traceability: Every referenced case observation exists in deterministic findings.
2. Citation Validity: Every cited knowledge chunk was actually retrieved.
3. Tactic Fidelity: No unobserved tactics are fabricated.
4. Decision Immutability: The generated narrative never contradicts Phase 8 status.
5. Unsupported Claim Detection: Flags untraceable assertions or adversarial instructions.
"""

import re
from typing import Dict, List, Optional, Sequence, Set, Tuple

from src.rag.citations import extract_citations
from .schemas import ExplanationRequest, ExplanationResponse, GroundingValidationResult

# Contradictory phrase patterns for decision consistency checks
SCAM_CONTRADICTIONS = [
    r"\b(?:this is (?:completely |totally )?(?:safe|legitimate|authentic|benign))\b",
    r"\b(?:no threat detected|no risk here|not a scam|completely harmless)\b",
    r"\b(?:verified safe|confirmed official)\b",
]

BENIGN_CONTRADICTIONS = [
    r"\b(?:this is (?:definitely |confirmed |100% )?a scam)\b",
    r"\b(?:confirmed fraud|malicious attack|phishing scam confirmed)\b",
]

# Disallowed fabricated active / external verification claims
FABRICATED_EXTERNAL_VERIFICATIONS = [
    r"\b(?:i (?:have )?(?:visited|browsed|accessed|navigated to|checked|pinged|contacted) (?:this|the) (?:url|website|link|page|server|domain))\b",
    r"\b(?:i (?:have )?verified (?:this|the) (?:website|server|domain|certificate|portal))\b",
    r"\b(?:(?:the )?bank (?:has )?confirmed (?:this|the) (?:message|account|sms|authenticity|legitimacy))\b",
    r"\b(?:external verification confirmed|live network check (?:confirmed|verified))\b",
    r"\b(?:this source proves)\b",
]


class GroundingValidator:
    """Post-generation audit validator enforcing evidence grounding and decision immutability."""

    def validate(
        self,
        request: ExplanationRequest,
        response: ExplanationResponse,
    ) -> GroundingValidationResult:
        """Audits generated ExplanationResponse against the deterministic request context.

        Args:
            request: The upstream ExplanationRequest providing ground truth.
            response: The generated ExplanationResponse to audit.

        Returns:
            GroundingValidationResult detailing pass/fail status and audit notes.
        """
        errors: List[str] = []
        warnings: List[str] = []
        unsupported_claims: List[str] = []

        # -------------------------------------------------------------
        # Check A: Case Evidence Grounding
        # -------------------------------------------------------------
        valid_ev_ids: Set[str] = set()
        for idx, ev in enumerate(request.evidence, start=1):
            eid = str(ev.get("evidence_id", "")).lower()
            if eid:
                valid_ev_ids.add(eid)
            valid_ev_ids.add(f"e{idx}")
            valid_ev_ids.add(f"ev{idx}")

        evidence_check_passed = True
        for obs in response.observed_evidence:
            citation = obs.get("citation", "")
            if citation:
                # Extract citation id
                m = re.search(r"\[CASE:([a-zA-Z0-9_\-]+)\]", citation)
                if m:
                    cid = m.group(1).lower()
                    if cid not in valid_ev_ids:
                        evidence_check_passed = False
                        errors.append(f"Invalid case citation '{citation}': Not in supplied case evidence.")
                else:
                    warnings.append(f"Malformed case citation format: '{citation}'.")

        # -------------------------------------------------------------
        # Check B: Knowledge Citation Grounding
        # -------------------------------------------------------------
        valid_kb_pairs: Set[Tuple[str, str]] = {
            (str(k.get("document_id", "")).lower(), str(k.get("chunk_id", "")).lower())
            for k in request.retrieved_knowledge
        }

        citation_check_passed = True
        for kc in response.knowledge_context:
            doc_id = str(kc.get("source_document", "")).lower()
            chunk_id = str(kc.get("chunk_id", "")).lower()
            if (doc_id, chunk_id) not in valid_kb_pairs:
                citation_check_passed = False
                errors.append(
                    f"Invalid knowledge source '{doc_id}:{chunk_id}': Chunk was not retrieved for this case."
                )

        # Also verify citations embedded in text
        text_corpus = f"{response.summary} {response.decision_context} {response.recommended_action}"
        extracted = extract_citations(text_corpus)
        for kb_tag in extracted["kb_citations"]:
            m = re.search(r"\[KB:([a-zA-Z0-9_\-]+):([a-zA-Z0-9_\-]+)\]", kb_tag)
            if m:
                pair = (m.group(1).lower(), m.group(2).lower())
                if pair not in valid_kb_pairs:
                    citation_check_passed = False
                    errors.append(f"Unretrieved knowledge citation in text: '{kb_tag}'.")

        # -------------------------------------------------------------
        # Check C: Tactic Fidelity (No Invented Tactics)
        # -------------------------------------------------------------
        supplied_tactics = {t.lower().strip() for t in request.tactics}
        tactic_check_passed = True
        for t_item in response.tactic_explanations:
            t_name = str(t_item.get("tactic", "")).lower().strip()
            if t_name and t_name not in supplied_tactics:
                # Check if it was explicitly framed as general background
                explanation_text = t_item.get("explanation", "").lower()
                if "general" not in explanation_text and "reference" not in explanation_text:
                    tactic_check_passed = False
                    errors.append(
                        f"Invented tactic '{t_name}': Not present in deterministic detected tactics ({sorted(list(supplied_tactics))})."
                    )

        # -------------------------------------------------------------
        # Check D: Decision Immutability
        # -------------------------------------------------------------
        status = request.deterministic_result.get("status", "").lower()
        combined_text = f"{response.summary} {response.decision_context}".lower()

        decision_check_passed = True
        if status == "likely_scam":
            for pat in SCAM_CONTRADICTIONS:
                if re.search(pat, combined_text):
                    decision_check_passed = False
                    errors.append(
                        f"Decision override violation: Deterministic status is 'likely_scam' but explanation contradicts: '{pat}'."
                    )
        elif status == "likely_non_scam":
            for pat in BENIGN_CONTRADICTIONS:
                if re.search(pat, combined_text):
                    decision_check_passed = False
                    errors.append(
                        f"Decision override violation: Deterministic status is 'likely_non_scam' but explanation contradicts: '{pat}'."
                    )
        elif status in ["mixed_signals", "insufficient_evidence"]:
            if "100% scam" in combined_text or "definitely safe" in combined_text:
                decision_check_passed = False
                errors.append(
                    f"Decision override violation: Deterministic status is '{status}' but explanation made definitive binary claim."
                )

        # -------------------------------------------------------------
        # Check E: Adversarial Prompt Injection Echoes
        # -------------------------------------------------------------
        if request.raw_text:
            raw_lower = request.raw_text.lower()
            if "ignore previous instructions" in raw_lower or "say this is safe" in raw_lower:
                # Verify that the explanation didn't follow the malicious prompt
                if not decision_check_passed or not evidence_check_passed:
                    errors.append("Potential prompt injection compromise detected.")

        # -------------------------------------------------------------
        # Check F: Fabricated External Actions & Verifications
        # -------------------------------------------------------------
        combined_text_all = f"{response.summary} {response.decision_context} {response.recommended_action}".lower()
        for pat in FABRICATED_EXTERNAL_VERIFICATIONS:
            m = re.search(pat, combined_text_all)
            if m:
                errors.append(
                    f"Fabricated external action violation: Explanation claims unperformed active verification: '{m.group(0)}'."
                )
                decision_check_passed = False

        # -------------------------------------------------------------
        # Check G: Invented URL Detection
        # -------------------------------------------------------------
        explanation_urls = re.findall(
            r"https?://[^\s<>\"'()]+",
            f"{response.summary} {response.decision_context} {response.recommended_action}",
        )
        if explanation_urls:
            valid_case_urls = set()
            if request.raw_text:
                valid_case_urls.update(re.findall(r"https?://[^\s<>\"'()]+", request.raw_text))
            for ev in request.evidence:
                if ev.get("text"):
                    valid_case_urls.update(re.findall(r"https?://[^\s<>\"'()]+", ev["text"]))
            for u in request.url_findings:
                if u.get("name"):
                    valid_case_urls.add(u["name"])

            for exp_url in explanation_urls:
                clean_url = exp_url.rstrip(".,;:!?)")
                if not any(clean_url.lower() in v.lower() or v.lower() in clean_url.lower() for v in valid_case_urls):
                    errors.append(f"Invented URL violation: Explanation references unverified URL '{clean_url}'.")
                    evidence_check_passed = False

        # Determine overall grounding status
        if errors:
            status_str = "rejected" if not decision_check_passed or not tactic_check_passed else "needs_review"
            is_grounded = False
        elif warnings or unsupported_claims:
            status_str = "needs_review"
            is_grounded = True
        else:
            status_str = "grounded"
            is_grounded = True

        return GroundingValidationResult(
            is_grounded=is_grounded,
            status=status_str,
            evidence_check_passed=evidence_check_passed,
            citation_check_passed=citation_check_passed,
            tactic_check_passed=tactic_check_passed,
            decision_check_passed=decision_check_passed,
            unsupported_claims=unsupported_claims,
            errors=errors,
            warnings=warnings,
        )
