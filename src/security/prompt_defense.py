"""Adversarial prompt injection defense and delimiter neutralization for ScamShield AI.

Features:
1. Pattern detection for known prompt injection strategies:
   - System prompt overrides and instruction resets.
   - Persona hijacking and jailbreak attempts (DAN, Developer Mode, Admin).
   - Prompt and system directive exfiltration.
   - Decision tampering (instructing LLM to declare scams safe).
   - Delimiter collisions and template breakout tags.
2. Safe delimiter neutralization:
   - Escapes boundary tags inside untrusted user content before prompt assembly.
   - Strips dangerous null bytes and hidden control characters.
3. Zero network dependencies; purely deterministic regex matching.
"""

import re
from typing import List, Tuple


# Declarative patterns matching adversarial prompt injection tactics
PROMPT_INJECTION_PATTERNS = [
    # 1. System Prompt Overrides & Instruction Resets
    (
        "system_override",
        re.compile(
            r"\b(?:ignore|disregard|forget|bypass|override)\s+(?:all\s+)?(?:previous|prior|earlier|above|system|developer)?\s*"
            r"(?:instructions|prompts|directives|rules|constraints|commands)\b",
            re.IGNORECASE,
        ),
    ),
    (
        "system_override_header",
        re.compile(
            r"\b(?:system\s+prompt\s+override|developer\s+override|admin\s+override|instruction\s+reset|override\s+instructions)\b",
            re.IGNORECASE,
        ),
    ),
    # 2. Persona Hijacking & Jailbreaks
    (
        "persona_hijack",
        re.compile(
            r"\b(?:you\s+are\s+now|act\s+as|pretend\s+(?:you\s+are|to\s+be)|switch\s+to|roleplay\s+as)\s+(?:an?\s+)?"
            r"(?:unrestricted|unfiltered|jailbroken|evil|god)?\s*"
            r"(?:developer|administrator|admin|system|root|dan|freedan|assistant|ai|bot)\b",
            re.IGNORECASE,
        ),
    ),
    (
        "developer_mode",
        re.compile(
            r"\b(?:developer\s+mode|jailbreak|unfiltered\s+mode|dan\s+mode)\s*(?:enabled|activated|engaged|on)?\b",
            re.IGNORECASE,
        ),
    ),
    # 3. Prompt Exfiltration
    (
        "prompt_exfiltration",
        re.compile(
            r"\b(?:reveal|show|print|display|output|repeat|leak|echo)\s+(?:your\s+)?(?:all\s+|entire\s+|the\s+)?"
            r"(?:words\s+above|system\s+prompt|initial\s+prompt|instructions|directives|rules)\b",
            re.IGNORECASE,
        ),
    ),
    # 4. Decision Tampering / Verdict Overrides
    (
        "verdict_tampering",
        re.compile(
            r"\b(?:declare|say|state|classify|mark|output|return|set)\s+(?:this\s+)?(?:message\s+|email\s+|sms\s+|verdict\s*[:=]\s*)?"
            r"(?:as\s+)?(?:is\s+)?(?:completely\s+|totally\s+)?(?:safe|legitimate|authentic|benign|not\s+a\s+scam|['\"]?likely_non_scam['\"]?)\b",
            re.IGNORECASE,
        ),
    ),
    (
        "classification_override",
        re.compile(
            r"\b(?:override\s+(?:the\s+)?(?:scam\s+)?(?:classification|verdict|status|determination)|"
            r"do\s+not\s+classify\s+(?:this\s+)?(?:as\s+)?(?:a\s+)?scam)\b",
            re.IGNORECASE,
        ),
    ),
    # 5. Delimiter Collision & Breakout
    (
        "delimiter_breakout",
        re.compile(
            r"(?:BEGIN|END)\s+(?:USER\s+CONTENT|DETERMINISTIC\s+FINDINGS|RETRIEVED\s+KNOWLEDGE|SYSTEM\s+INSTRUCTION)|"
            r"</?user_input>|</?system>|```(?:system|prompt)",
            re.IGNORECASE,
        ),
    ),
]

# Delimiter markers to neutralize inside untrusted content
DELIMITER_ESCAPES = [
    (re.compile(r"BEGIN\s+USER\s+CONTENT", re.IGNORECASE), "[DELIMITER_ESCAPED: BEGIN USER CONTENT]"),
    (re.compile(r"END\s+USER\s+CONTENT", re.IGNORECASE), "[DELIMITER_ESCAPED: END USER CONTENT]"),
    (re.compile(r"BEGIN\s+DETERMINISTIC\s+FINDINGS", re.IGNORECASE), "[DELIMITER_ESCAPED: BEGIN DETERMINISTIC FINDINGS]"),
    (re.compile(r"END\s+DETERMINISTIC\s+FINDINGS", re.IGNORECASE), "[DELIMITER_ESCAPED: END DETERMINISTIC FINDINGS]"),
    (re.compile(r"BEGIN\s+RETRIEVED\s+KNOWLEDGE", re.IGNORECASE), "[DELIMITER_ESCAPED: BEGIN RETRIEVED KNOWLEDGE]"),
    (re.compile(r"END\s+RETRIEVED\s+KNOWLEDGE", re.IGNORECASE), "[DELIMITER_ESCAPED: END RETRIEVED KNOWLEDGE]"),
    (re.compile(r"CRITICAL\s+INSTRUCTION", re.IGNORECASE), "[DELIMITER_ESCAPED: CRITICAL INSTRUCTION]"),
    (re.compile(r"</?user_input>", re.IGNORECASE), "[DELIMITER_ESCAPED: TAG]"),
    (re.compile(r"</?system>", re.IGNORECASE), "[DELIMITER_ESCAPED: TAG]"),
]


def detect_prompt_injection(text: str) -> Tuple[bool, List[str]]:
    """Analyzes text for adversarial prompt injection attempts.

    Args:
        text: Input message string.

    Returns:
        Tuple of (is_detected: bool, matched_tactics: List[str]).
    """
    if not isinstance(text, str) or not text.strip():
        return False, []

    matched: List[str] = []
    for tactic_name, pattern in PROMPT_INJECTION_PATTERNS:
        if pattern.search(text):
            matched.append(tactic_name)

    return len(matched) > 0, matched


def sanitize_prompt_user_content(text: str) -> str:
    """Neutralizes delimiter markers and control characters from untrusted text before LLM prompt inclusion.

    Args:
        text: Raw user text.

    Returns:
        Sanitized text safe for prompt template interpolation.
    """
    if not isinstance(text, str):
        return ""

    sanitized = text

    # 1. Strip null bytes and hazardous low control characters
    sanitized = sanitized.replace("\x00", "")

    # 2. Escape prompt boundary tags so attacker cannot break out of user content block
    for pattern, replacement in DELIMITER_ESCAPES:
        sanitized = pattern.sub(replacement, sanitized)

    return sanitized
