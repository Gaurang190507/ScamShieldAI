"""Contextual Tactic Detection and Disambiguation Layer for ScamShield AI Phase 17.

Implements:
- Fix #2: Brand Mention vs. Brand Impersonation Disambiguation (Routine Delivery Codes)
- Fix #5: Contextual Tactic Detection Enhancement Layer (Coercive Authority, Conversational Urgency,
  Indirect Payment Demand, Isolation Enforcement)

All rules are deterministic, fully offline, grounded in textual evidence spans, and
distinguish benign transactional notifications from active manipulative exploitation.
"""

from dataclasses import dataclass, field
import re
from typing import Any, Dict, List, Optional, Set, Tuple

from src.tactics.schemas import DetectedTactic, EvidenceSpan


# -----------------------------------------------------------------------------
# Fix #2: Routine Delivery Notification / Handover Patterns (Benign Disambiguation)
# -----------------------------------------------------------------------------

DELIVERY_HANDOVER_PATTERNS = [
    re.compile(r"\b(?:out\s+for\s+delivery|out\s+for\s+dispatch)\b", re.IGNORECASE),
    re.compile(r"\b(?:delivery\s+(?:agent|associate|partner|driver|boy|executive))\b", re.IGNORECASE),
    re.compile(r"\b(?:share\s+(?:delivery\s+code|otp|pin)\s+(?:with|to)\s+(?:the\s+)?(?:driver|agent|associate|courier|delivery))\b", re.IGNORECASE),
    re.compile(r"\b(?:at\s+(?:your\s+)?(?:door|doorstep))\b", re.IGNORECASE),
    re.compile(r"\b(?:package|parcel|order)\s+(?:is\s+arriving|arriving\s+today|will\s+be\s+delivered)\b", re.IGNORECASE),
    re.compile(r"\b(?:handover|hand\s+over)\s+(?:code|pin|otp)\b", re.IGNORECASE),
    re.compile(r"\b(?:delivery\s+code)\s*(?::\s*|\s+is\s+)?\d{4,8}\b", re.IGNORECASE),
]

# Signals indicating that a delivery notification may actually be malicious
DELIVERY_EXPLOIT_PATTERNS = [
    re.compile(r"\b(?:pay|payment|fee|charge|cost|rupees|rs\.?|inr)\s*(?:\d+|pending|due|clear|release)\b", re.IGNORECASE),
    re.compile(r"\b(?:update\s+address|confirm\s+address|incomplete\s+address|re-?delivery\s+fee)\b", re.IGNORECASE),
    re.compile(r"\b(?:customs\s+(?:duty|clearance|hold|penalty|charge))\b", re.IGNORECASE),
    re.compile(r"\b(?:click|visit|link|http|https|www|\.com|\.in|\.top|\.xyz)\b", re.IGNORECASE),
    re.compile(r"\b(?:suspended|blocked|seized|arrest|legal\s+action|police)\b", re.IGNORECASE),
    re.compile(r"\b(?:install|download|anydesk|teamviewer|rustdesk|quicksupport)\b", re.IGNORECASE),
    re.compile(r"\b(?:bank\s+account|debit\s+card|credit\s+card|cvv|netbanking)\b", re.IGNORECASE),
]


# -----------------------------------------------------------------------------
# Fix #5: Contextual Tactic Patterns
# -----------------------------------------------------------------------------

# 1. Coercive Authority & Legal Threats
# Positive: "Digital arrest judicial custody CBI inquiry pending under section 420."
# Negative: "The Ministry of Health announced a national vaccination drive."
COERCIVE_AUTHORITY_PATTERNS = [
    (
        "p17_auth_001",
        re.compile(r"\b(?:digital\s+arrest|virtual\s+arrest)\b", re.IGNORECASE),
        "coercive_authority",
        "high",
        "Fabricated coercive digital arrest assertion",
    ),
    (
        "p17_auth_002",
        re.compile(r"\b(?:judicial\s+custody|police\s+custody|custody\s+warrant)\b", re.IGNORECASE),
        "coercive_authority",
        "high",
        "Threat of imminent judicial custody or arrest warrant",
    ),
    (
        "p17_auth_003",
        re.compile(r"\b(?:cbi|enforcement\s+directorate|narcotics\s+control\s+bureau|ncb|mha|cyber\s+crime\s+cell)\s+(?:inquiry|investigation|notice|summons|warrant|case)\b", re.IGNORECASE),
        "coercive_authority",
        "high",
        "Coercive law enforcement agency summons or investigation claim",
    ),
    (
        "p17_auth_004",
        re.compile(r"\b(?:warrant\s+(?:has\s+been\s+)?issued|statutory\s+(?:non-?compliance\s+)?penalty|legal\s+summons\s+issued)\b", re.IGNORECASE),
        "coercive_authority",
        "high",
        "Asserted formal arrest warrant or statutory penal proceedings",
    ),
]

# 2. Conversational Urgency & Coercive Deadlines
# Positive: "Action required immediately before close of business to avoid legal prosecution."
# Negative: "Our support desk is open from 9 AM to 6 PM on weekdays."
CONVERSATIONAL_URGENCY_PATTERNS = [
    (
        "p17_urg_001",
        re.compile(r"\b(?:action\s+required\s+within\s+(?:\d+|24|48|twelve|twenty[- ]four)\s+hours\s+to\s+avoid)\b", re.IGNORECASE),
        "conversational_urgency",
        "high",
        "Coercive artificial deadline coupled with threat consequence",
    ),
    (
        "p17_urg_002",
        re.compile(r"\b(?:before\s+close\s+of\s+business\s+today|within\s+the\s+next\s+(?:\d+|one|two)\s+hours?\s+strictly)\b", re.IGNORECASE),
        "conversational_urgency",
        "medium",
        "Imminent deadline pressure forcing hurried victim compliance",
    ),
    (
        "p17_urg_003",
        re.compile(r"\b(?:final\s+notice\s+before\s+(?:warrant|arrest|legal\s+action|police\s+enquiry|account\s+freez))\b", re.IGNORECASE),
        "conversational_urgency",
        "high",
        "Final ultimatum exerting psychological duress",
    ),
]

# 3. Indirect Payment Demand (Asset transfer, safety deposits, clearing fees)
# Positive: "Deposit settlement funds into the RBI safety reserve account for clearance."
# Negative: "Your salary has been deposited into your savings account."
INDIRECT_PAYMENT_PATTERNS = [
    (
        "p17_pay_001",
        re.compile(r"\b(?:safety\s+(?:reserve\s+)?account|verification\s+account|escrow\s+clearance\s+account|rbi\s+safety\s+wallet)\b", re.IGNORECASE),
        "indirect_payment_demand",
        "high",
        "Demanding transfer into deceptive official safety or escrow reserve",
    ),
    (
        "p17_pay_002",
        re.compile(r"\b(?:liquidate\s+(?:your\s+)?(?:holdings|shares|investments|fd|deposits)\s+(?:to|for)\s+(?:secure|bond|safety|clearance))\b", re.IGNORECASE),
        "indirect_payment_demand",
        "high",
        "Coercing victim to liquidate assets into purported bond or clearance fund",
    ),
    (
        "p17_pay_003",
        re.compile(r"\b(?:refundable\s+(?:security|verification|clearance|statutory)\s+(?:deposit|fee|amount))\b", re.IGNORECASE),
        "indirect_payment_demand",
        "high",
        "Luring payment under the guise of a refundable verification deposit",
    ),
]

# 4. Isolation & Secrecy Enforcement
# Positive: "Maintain strict confidentiality. Do not disclose this procedure to bank branch staff or family."
# Negative: "Please read our privacy policy regarding customer data confidentiality."
ISOLATION_PATTERNS = [
    (
        "p17_iso_001",
        re.compile(r"\b(?:maintain\s+strict\s+confidentiality|keep\s+(?:this\s+)?matter\s+strictly\s+confidential)\b", re.IGNORECASE),
        "isolation_enforcement",
        "high",
        "Demanding total confidentiality to isolate the victim",
    ),
    (
        "p17_iso_002",
        re.compile(r"\b(?:do\s+not\s+(?:disclose|share|mention)\s+(?:to|with)\s+(?:family|relatives|friends|bank\s+officials|branch\s+staff))\b", re.IGNORECASE),
        "isolation_enforcement",
        "high",
        "Explicitly instructing victim not to consult family or bank personnel",
    ),
    (
        "p17_iso_003",
        re.compile(r"\b(?:remain\s+on\s+(?:the\s+)?(?:video\s+)?call\s+(?:in|inside)\s+(?:a\s+)?(?:closed|private|isolated)\s+room)\b", re.IGNORECASE),
        "isolation_enforcement",
        "high",
        "Coercing victim into physical and communication isolation during fraud",
    ),
]


@dataclass
class DisambiguationRecord:
    """Audit entry documenting contextual tactic disambiguation."""

    original_tactic: str
    action: str  # "reclassified", "preserved", "added"
    new_tactic: Optional[str]
    rule_id: str
    reason: str
    confidence: float

    def to_dict(self) -> Dict[str, Any]:
        return {
            "original_tactic": self.original_tactic,
            "action": self.action,
            "new_tactic": self.new_tactic,
            "rule_id": self.rule_id,
            "reason": self.reason,
            "confidence": self.confidence,
        }


@dataclass
class ContextualEnhancementResult:
    """Container for post-Phase-16 contextual tactic enhancement."""

    original_tactics: List[str]
    enhanced_tactics: List[str]
    tactic_objects: List[DetectedTactic]
    disambiguations: List[DisambiguationRecord] = field(default_factory=list)
    new_evidence_spans: List[EvidenceSpan] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "original_tactics": self.original_tactics,
            "enhanced_tactics": self.enhanced_tactics,
            "disambiguations": [d.to_dict() for d in self.disambiguations],
            "new_evidence_count": len(self.new_evidence_spans),
        }


class ContextualTacticEnhancer:
    """Enhances tactic detection with contextual disambiguation and modern coercion patterns.

    Isolated post-Phase-16 enhancement layer:
    - Never modifies frozen Phase 6 rule definitions.
    - Operates on Phase 6 outputs and raw message context.
    - Resolves routine brand mentions (delivery handovers) vs. brand impersonation.
    - Extracts high-severity modern tactics (digital arrest, safe accounts, isolation).
    """

    def __init__(self):
        self.coercive_patterns = COERCIVE_AUTHORITY_PATTERNS
        self.urgency_patterns = CONVERSATIONAL_URGENCY_PATTERNS
        self.payment_patterns = INDIRECT_PAYMENT_PATTERNS
        self.isolation_patterns = ISOLATION_PATTERNS

    def enhance(
        self,
        text: str,
        detected_tactics: List[str],
        existing_evidence: Optional[List[Dict[str, Any]]] = None,
        urls: Optional[List[str]] = None,
    ) -> ContextualEnhancementResult:
        """Runs contextual tactic enhancement and disambiguation.

        Args:
            text: Raw or normalized message string.
            detected_tactics: List of tactic names from Phase 6.
            existing_evidence: Raw evidence dictionaries from Phase 6.
            urls: Pre-extracted URLs associated with message.

        Returns:
            ContextualEnhancementResult with updated tactics and audit records.
        """
        if not isinstance(text, str) or not text.strip():
            return ContextualEnhancementResult(
                original_tactics=list(detected_tactics),
                enhanced_tactics=list(detected_tactics),
                tactic_objects=[],
            )

        working_tactics: List[str] = list(detected_tactics)
        disambiguations: List[DisambiguationRecord] = []
        new_evidence_spans: List[EvidenceSpan] = []
        new_tactics_dict: Dict[str, DetectedTactic] = {}

        # ---------------------------------------------------------------------
        # Fix #2: Delivery Code / Brand Impersonation Disambiguation
        # ---------------------------------------------------------------------
        if "impersonation" in working_tactics:
            is_delivery_handover = any(p.search(text) for p in DELIVERY_HANDOVER_PATTERNS)
            has_exploit_signals = any(p.search(text) for p in DELIVERY_EXPLOIT_PATTERNS)
            has_suspicious_urls = bool(urls and len(urls) > 0)

            if is_delivery_handover and not has_exploit_signals and not has_suspicious_urls:
                # Reclassify from active exploitation impersonation to benign brand_mention
                working_tactics = [t for t in working_tactics if t != "impersonation"]
                working_tactics.append("brand_mention")
                disambiguations.append(
                    DisambiguationRecord(
                        original_tactic="impersonation",
                        action="reclassified",
                        new_tactic="brand_mention",
                        rule_id="p17_delivery_disambiguation_001",
                        reason=(
                            "Brand reference appears in legitimate physical delivery handover context "
                            "(out for delivery / door delivery code) with zero coercive, credential, "
                            "or payment exploitation signals."
                        ),
                        confidence=0.95,
                    )
                )

        # ---------------------------------------------------------------------
        # Fix #5: Contextual Tactic Extraction
        # ---------------------------------------------------------------------
        all_pattern_groups = [
            self.coercive_patterns,
            self.urgency_patterns,
            self.payment_patterns,
            self.isolation_patterns,
        ]

        for p_group in all_pattern_groups:
            for rule_id, regex, tactic_name, severity, reason in p_group:
                for match in regex.finditer(text):
                    span = EvidenceSpan(
                        matched_text=match.group(0),
                        start=match.start(),
                        end=match.end(),
                        rule_id=rule_id,
                        severity=severity,
                        reason=reason,
                    )
                    new_evidence_spans.append(span)

                    if tactic_name not in working_tactics:
                        working_tactics.append(tactic_name)

                    if tactic_name not in new_tactics_dict:
                        new_tactics_dict[tactic_name] = DetectedTactic(
                            tactic=tactic_name,
                            severity=severity,
                            evidence_strength="high" if severity == "high" else "medium",
                            evidence=[span],
                        )
                    else:
                        new_tactics_dict[tactic_name].evidence.append(span)

        return ContextualEnhancementResult(
            original_tactics=list(detected_tactics),
            enhanced_tactics=working_tactics,
            tactic_objects=list(new_tactics_dict.values()),
            disambiguations=disambiguations,
            new_evidence_spans=new_evidence_spans,
        )
