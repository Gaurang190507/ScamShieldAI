"""Deterministic feature extraction from raw message text.

CRITICAL PRODUCT PRINCIPLE:
Features are observable signals and structural properties, NOT scam labels.
This module extracts empirical measurements without making scam classifications.
"""

import re
import string
import unicodedata
from typing import Tuple, Dict, Any, Optional, List

from .schemas import TextFeatures, ExtractedEntities
from .extract_entities import extract_all_entities


# Regex for OTP and multi-factor authentication tokens
OTP_REGEX = re.compile(
    r"\b("
    r"otp|"
    r"one[-\s]time\s+pass(?:word|code)|"
    r"verification\s+code|"
    r"security\s+code|"
    r"auth(?:entication)?\s+code|"
    r"login\s+code"
    r")\b",
    re.IGNORECASE,
)

# Invisible, zero-width, and directional override Unicode codepoints
_SUSPICIOUS_INVISIBLE_CHARS = frozenset([
    "\u200b",  # Zero-width space
    "\u200d",  # Zero-width joiner (outside emoji sequences)
    "\ufeff",  # Zero-width no-break space / BOM
    "\u200e",  # Left-to-right mark
    "\u200f",  # Right-to-left mark
    "\u202a",  # LTR embedding
    "\u202b",  # RTL embedding
    "\u202c",  # Pop directional formatting
    "\u202d",  # LTR override
    "\u202e",  # RTL override (common in file extension / text flipping spoofs)
    "\u2060",  # Word joiner
])

# Repeated punctuation streak pattern (2 or more consecutive punctuation marks)
PUNCT_STREAK_REGEX = re.compile(
    r"([!?,.:;\-–—~@#$%^&*()_+=\[\]{}|\\/<>\"']{2,})"
)


def is_otp_related(text: str) -> bool:
    """Detects whether text contains explicit OTP or authentication code terminology.

    Args:
        text: Input string.

    Returns:
        Boolean indicating presence of OTP / verification code terms.
    """
    if not isinstance(text, str):
        return False
    return bool(OTP_REGEX.search(text))


def count_emojis(text: str) -> int:
    """Counts Unicode emoji symbols and pictographs without third-party dependencies.

    Args:
        text: Input string.

    Returns:
        Count of emoji characters in the string.
    """
    if not isinstance(text, str):
        return 0
    count = 0
    for ch in text:
        code = ord(ch)
        if (
            (0x1F600 <= code <= 0x1F64F)  # Emoticons
            or (0x1F300 <= code <= 0x1F5FF)  # Misc Symbols and Pictographs
            or (0x1F680 <= code <= 0x1F6FF)  # Transport and Map
            or (0x1F700 <= code <= 0x1F77F)  # Alchemical
            or (0x1F780 <= code <= 0x1F7FF)  # Geometric Shapes Extended
            or (0x1F800 <= code <= 0x1F8FF)  # Supplemental Arrows-C
            or (0x1F900 <= code <= 0x1F9FF)  # Supplemental Symbols and Pictographs
            or (0x1FA00 <= code <= 0x1FA6F)  # Chess Symbols
            or (0x1FA70 <= code <= 0x1FAFF)  # Symbols and Pictographs Extended-A
            or (0x2600 <= code <= 0x26FF)  # Miscellaneous Symbols (e.g. ⚠️, ⚡)
            or (0x2700 <= code <= 0x27BF)  # Dingbats
        ):
            count += 1
    return count


def analyze_punctuation_repetition(text: str) -> Tuple[bool, int, int]:
    """Analyzes punctuation repetition streaks (e.g., '!!!', '????', '$$$').

    Args:
        text: Input string.

    Returns:
        Tuple of (has_repeated_punctuation: bool, max_consecutive_punctuation: int, repeated_punctuation_count: int).
    """
    if not isinstance(text, str):
        return False, 0, 0
    matches = PUNCT_STREAK_REGEX.findall(text)
    if not matches:
        return False, 0, 0
    max_streak = max(len(m) for m in matches)
    return True, max_streak, len(matches)


def has_suspicious_unicode(text: str) -> bool:
    """Detects unusual Unicode indicators (zero-width chars, math alphanumeric symbols, mixed-script homoglyphs).

    Limitation: This is an empirical indicator for evasive text formatting; it is not definitive proof of fraud.

    Args:
        text: Input string.

    Returns:
        Boolean indicating presence of suspicious Unicode formatting.
    """
    if not isinstance(text, str):
        return False

    for ch in text:
        # 1. Invisible and directional override characters
        if ch in _SUSPICIOUS_INVISIBLE_CHARS:
            return True
        code = ord(ch)
        # 2. Mathematical Alphanumeric Symbols (frequently abused to bypass simple keyword filters)
        if 0x1D400 <= code <= 0x1D7FF:
            return True

    # 3. Mixed script within a single token (e.g., Latin mixed with Cyrillic or Greek lookalikes)
    tokens = re.findall(r"\S+", text)
    for token in tokens:
        has_latin = any("a" <= c <= "z" or "A" <= c <= "Z" for c in token)
        has_cyrillic = any("\u0400" <= c <= "\u04FF" for c in token)
        has_greek = any("\u0370" <= c <= "\u03FF" for c in token)
        if has_latin and (has_cyrillic or has_greek):
            return True

    return False


def extract_text_features(
    text: str,
    entities: Optional[ExtractedEntities] = None,
) -> TextFeatures:
    """Extracts all deterministic numerical, structural, and behavioral indicator features.

    Args:
        text: Raw authoritative message string.
        entities: Optional pre-extracted entities dataclass. If omitted, entities are extracted.

    Returns:
        TextFeatures dataclass containing observable signal measurements.
    """
    if not isinstance(text, str):
        text = ""

    # Entity features
    ents = entities or extract_all_entities(text)
    url_count = len(ents.urls)
    has_url = url_count > 0

    phone_count = len(ents.phone_numbers)
    has_phone = phone_count > 0

    email_count = len(ents.emails)
    has_email = email_count > 0

    currency_count = len(ents.currency_mentions)
    has_currency = currency_count > 0

    # Parse numeric amount values for currencies
    amount_values: List[float] = []
    for mention in ents.currency_mentions:
        num_m = re.search(r"\d+(?:,\d{3})*(?:\.\d+)?", mention)
        if num_m:
            try:
                amount_values.append(float(num_m.group(0).replace(",", "")))
            except ValueError:
                pass

    # Basic length and character features
    char_count = len(text)
    words = text.split()
    word_count = len(words)

    digit_count = sum(1 for c in text if c.isdigit())
    uppercase_count = sum(1 for c in text if c.isupper())

    uppercase_ratio = round(uppercase_count / max(char_count, 1), 4)
    digit_ratio = round(digit_count / max(char_count, 1), 4)

    exclamation_count = text.count("!")
    question_mark_count = text.count("?")

    # Special characters: non-alphanumeric and non-whitespace
    special_char_count = sum(1 for c in text if not c.isalnum() and not c.isspace())

    lines = text.splitlines()
    line_count = len(lines) if text else 0

    emojis = count_emojis(text)

    # Repetition and Unicode anomalies
    has_rep_punct, max_punct, punct_streak_count = analyze_punctuation_repetition(text)
    suspicious_unicode = has_suspicious_unicode(text)
    otp_flag = is_otp_related(text)

    return TextFeatures(
        character_count=char_count,
        word_count=word_count,
        digit_count=digit_count,
        uppercase_count=uppercase_count,
        uppercase_ratio=uppercase_ratio,
        digit_ratio=digit_ratio,
        exclamation_count=exclamation_count,
        question_mark_count=question_mark_count,
        special_character_count=special_char_count,
        line_count=line_count,
        emoji_count=emojis,
        has_url=has_url,
        url_count=url_count,
        has_phone_number=has_phone,
        phone_count=phone_count,
        has_email=has_email,
        email_count=email_count,
        has_currency=has_currency,
        currency_count=currency_count,
        amount_values=amount_values,
        otp_related=otp_flag,
        has_repeated_punctuation=has_rep_punct,
        max_consecutive_punctuation=max_punct,
        repeated_punctuation_count=punct_streak_count,
        has_suspicious_unicode=suspicious_unicode,
    )
