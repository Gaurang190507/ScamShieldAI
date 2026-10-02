"""Rule-based pattern matcher for tactical scam indicators.

Identifies behavioral tactics: urgency, impersonation, threats, OTP/credential
requests, unusual payments, and fake support patterns.
"""

from typing import Dict, List, Any
import re


class RuleDetector:
    """Heuristic rule engine detecting specific scam tactics in text."""

    def __init__(self):
        # Placeholder regex patterns for initial behavioral indicators
        self.patterns = {
            "urgency": [
                re.compile(r"\b(immediately|urgent|within\s+\d+\s*(hours?|mins?)|act\s+now|expires?|suspended)\b", re.I),
            ],
            "threats": [
                re.compile(r"\b(arrest|legal\s+action|police|lawsuit|penalty|frozen|blocked)\b", re.I),
            ],
            "otp_or_credentials": [
                re.compile(r"\b(otp|one[-\s]?time\s+password|pin|cvv|password|verification\s+code)\b", re.I),
            ],
            "payment_demands": [
                re.compile(r"\b(wire\s+transfer|gift\s+card|crypto|bitcoin|pay\s+now|fee\s+required)\b", re.I),
            ],
            "impersonation": [
                re.compile(r"\b(official\s+support|bank\s+alert|tax\s+department|customs|security\s+team)\b", re.I),
            ],
        }

    def detect_tactics(self, text: str) -> Dict[str, List[str]]:
        """Scans input text against tactical heuristic rules.

        Returns:
            Dictionary mapping identified tactic category to list of matched phrases.
        """
        detected: Dict[str, List[str]] = {}
        for tactic, regex_list in self.patterns.items():
            matches = []
            for reg in regex_list:
                found = reg.findall(text)
                if found:
                    # Flatten matched groups if any
                    for m in found:
                        matches.append(m if isinstance(m, str) else m[0])
            if matches:
                detected[tactic] = list(set(matches))
        return detected
