"""Deterministic text normalization preserving evidence and raw representations."""

import re
import unicodedata


# Control characters to strip (ASCII 0-8, 11-12, 14-31, 127) excluding \t (9) and \n (10)
_CONTROL_CHAR_REGEX = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")


def normalize_unicode(text: str) -> str:
    """Applies conservative Unicode normalization (NFKC) while stripping invisible control chars.

    Preserves emojis, punctuation, currency symbols (₹, £, $, €, etc.), and scripts.

    Args:
        text: Input string.

    Returns:
        Unicode-normalized string.
    """
    if not isinstance(text, str):
        return ""
    # Normalize via NFKC (combining characters, fullwidth/halfwidth compatibility)
    normalized = unicodedata.normalize("NFKC", text)
    # Strip unwanted control characters while preserving tabs and newlines
    clean = _CONTROL_CHAR_REGEX.sub("", normalized)
    return clean


def normalize_whitespace(text: str) -> str:
    """Normalizes excessive horizontal whitespace and standardized newlines.

    Args:
        text: Input string.

    Returns:
        String with single horizontal spaces between tokens and stripped edges.
    """
    if not isinstance(text, str):
        return ""
    # Standardize CRLF and CR to standard LF
    standard_newlines = text.replace("\r\n", "\n").replace("\r", "\n")
    # Collapse multiple horizontal whitespace characters (spaces, tabs) into a single space per line
    lines = [re.sub(r"[ \t]+", " ", line).strip() for line in standard_newlines.split("\n")]
    # Remove excessive blank lines (>2) while preserving paragraph separation
    collapsed_lines = []
    blank_streak = 0
    for line in lines:
        if not line:
            blank_streak += 1
            if blank_streak <= 1:
                collapsed_lines.append(line)
        else:
            blank_streak = 0
            collapsed_lines.append(line)
    return "\n".join(collapsed_lines).strip()


def build_normalized_text(text: str) -> str:
    """Builds a conservative normalized version of the message.

    Preserves exact casing, punctuation, numbers, URLs, and emojis.

    Args:
        text: Original message string.

    Returns:
        Conservative normalized text.
    """
    if not isinstance(text, str):
        return ""
    u_norm = normalize_unicode(text)
    return normalize_whitespace(u_norm)


def build_analysis_text(text: str) -> str:
    """Builds a derived analysis text for classical NLP consumption.

    Lowercases text while strictly preserving:
    - URLs
    - numbers
    - punctuation
    - currency symbols
    - emojis
    - all words (no stopword removal, no stemming)

    Args:
        text: Original message string.

    Returns:
        Lowercased, whitespace-normalized analysis text string.
    """
    if not isinstance(text, str):
        return ""
    norm = build_normalized_text(text)
    return norm.lower()


def clean_text(text: str) -> str:
    """Legacy helper preserved for backward compatibility."""
    return build_normalized_text(text)
