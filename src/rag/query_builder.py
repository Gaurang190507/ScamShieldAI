"""Structured retrieval query builder for ScamShield AI Phase 10.

OPERATIONAL PRINCIPLE:
Constructs search queries from verified, structured upstream findings (tactics,
URL anomalies, visual indicators, requested actions) rather than blindly echoing
untrusted raw user text. This prevents prompt manipulation and off-topic lexical noise.
"""

from typing import Any, Dict, List, Optional, Set, Union

from src.aggregation.schemas import CaseAssessmentResult, EvidenceItem
from .schemas import RetrievalQuery

# Known entity and keyword mappings for targeted retrieval expansion
KEYWORD_ASSOCIATIONS: Dict[str, List[str]] = {
    "urgency": ["urgent", "deadline", "immediate", "suspension", "deactivation"],
    "impersonation": ["official", "police", "cbi", "customs", "bank", "digital arrest", "regulatory"],
    "payment_request": ["payment", "transfer", "upi", "qr code", "escrow", "refund"],
    "lottery": ["lottery", "prize", "winner", "reward", "advance fee", "customs"],
    "kyc": ["kyc", "pan", "aadhaar", "sim card", "document verification", "disconnect"],
    "credential_harvesting": ["otp", "password", "pin", "login", "credentials", "verification"],
    "delivery": ["parcel", "courier", "package", "address update", "customs fee"],
    "apk_sideload": ["apk", "download app", "trojan", "accessibility", "remote access"],
}


def build_retrieval_query(
    case_result: Optional[CaseAssessmentResult] = None,
    signals: Optional[Dict[str, Any]] = None,
    evidence_items: Optional[List[EvidenceItem]] = None,
    override_query_text: Optional[str] = None,
) -> RetrievalQuery:
    """Constructs a focused RetrievalQuery from structured case findings.

    Args:
        case_result: Phase 8 CaseAssessmentResult instance.
        signals: Optional explicit dictionary of signal outputs.
        evidence_items: Optional explicit list of EvidenceItem instances.
        override_query_text: Optional direct query string for testing/manual search.

    Returns:
        Structured RetrievalQuery dataclass instance.
    """
    if override_query_text:
        return RetrievalQuery(
            query_text=override_query_text.strip(),
            extracted_keywords=[w.lower() for w in override_query_text.split() if len(w) > 3],
        )

    tactics: Set[str] = set()
    url_findings: Set[str] = set()
    visual_findings: Set[str] = set()
    requested_actions: Set[str] = set()
    target_assets: Set[str] = set()
    extracted_keywords: Set[str] = set()

    # Extract from CaseAssessmentResult
    if case_result is not None:
        raw_signals = case_result.signals
        evidence = case_result.evidence

        # Phase 6 tactics
        phase6_tactics = raw_signals.get("phase6_tactics", {})
        if isinstance(phase6_tactics, dict):
            tactics.update(phase6_tactics.get("detected_tactics", []))

        # Phase 4 URL signals
        phase4_urls = raw_signals.get("phase4_url", {})
        if isinstance(phase4_urls, dict):
            for sig in phase4_urls.get("signals", []):
                if isinstance(sig, dict):
                    url_findings.add(sig.get("name", ""))
                elif isinstance(sig, str):
                    url_findings.add(sig)

        # Inspect atomic evidence items
        for ev in evidence:
            ev_name = ev.name.lower()
            ev_type = ev.type.lower()

            if ev.text:
                for word in ev.text.lower().split():
                    if len(word) > 3 and word.isalnum():
                        extracted_keywords.add(word)

            if ev_type == "tactic":
                tactics.add(ev.name)
            elif ev_type == "url_signal":
                url_findings.add(ev.name)
            elif "qr" in ev_name:
                visual_findings.add("qr_code")
                extracted_keywords.add("qr code")
            elif "banner" in ev_name or "alert" in ev_name:
                visual_findings.add("urgent_banner")

            if "payment" in ev_name or "refund" in ev_name:
                requested_actions.add("payment_action")
                target_assets.add("bank_account")
            if "otp" in ev_name or "password" in ev_name:
                requested_actions.add("credential_disclosure")
                target_assets.add("otp_tokens")
            if "kyc" in ev_name or "pan" in ev_name or "aadhaar" in ev_name:
                requested_actions.add("identity_verification")
                target_assets.add("government_id")

    # Expand keywords from detected tactics
    for t in tactics:
        t_lower = t.lower()
        if t_lower in KEYWORD_ASSOCIATIONS:
            extracted_keywords.update(KEYWORD_ASSOCIATIONS[t_lower])
        else:
            extracted_keywords.add(t_lower.replace("_", " "))

    for u in url_findings:
        u_clean = u.lower().replace("_", " ")
        if u_clean:
            extracted_keywords.add(u_clean)

    # Compile query text tokens
    query_parts: List[str] = []
    if tactics:
        query_parts.append(" ".join(sorted(tactics)).replace("_", " "))
    if url_findings:
        query_parts.append(" ".join(sorted(url_findings)).replace("_", " "))
    if visual_findings:
        query_parts.append(" ".join(sorted(visual_findings)).replace("_", " "))
    if requested_actions:
        query_parts.append(" ".join(sorted(requested_actions)).replace("_", " "))
    if target_assets:
        query_parts.append(" ".join(sorted(target_assets)).replace("_", " "))
    if extracted_keywords:
        query_parts.append(" ".join(sorted(extracted_keywords)))

    compiled_query = " ".join(query_parts).strip()
    if not compiled_query:
        compiled_query = "citizen cyber safety awareness official guidelines verification best practices"

    return RetrievalQuery(
        query_text=compiled_query,
        detected_tactics=sorted(list(tactics)),
        requested_actions=sorted(list(requested_actions)),
        target_assets=sorted(list(target_assets)),
        url_findings=sorted(list(url_findings)),
        visual_findings=sorted(list(visual_findings)),
        extracted_keywords=sorted(list(extracted_keywords)),
    )
