"""Deterministic entity extraction for URLs, phone numbers, emails, and currencies.

OPERATIONAL SAFETY:
- Completely offline: ZERO network requests, ZERO DNS queries, ZERO domain resolution.
- Extracted URLs and emails are treated strictly as passive text data.
"""

from typing import List, Tuple, Dict, Any, Optional
from urllib.parse import urlparse
import re

from .schemas import ExtractedEntities


# Deterministic URL matching pattern
URL_REGEX = re.compile(
    r"(?:https?://|www\.)[^\s/$.?#].[^\s]*",
    re.IGNORECASE,
)

# Standard email address pattern
EMAIL_REGEX = re.compile(
    r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"
)

# Currency and monetary amount patterns
CURRENCY_REGEX = re.compile(
    r"(?:"
    r"(?:[\$£€¥₹]|Rs\.?|INR)\s*\d+(?:,\d{3})*(?:\.\d+)?(?:\s*(?:k|m|million|billion|lakh|crore))?"
    r"|\b\d+(?:,\d{3})*(?:\.\d+)?\s*(?:rupees?|dollars?|pounds?|euros?|inr|usd|gbp|eur|p/min|ppm|p/day|\s*p\b)"
    r")",
    re.IGNORECASE,
)

# Candidate phone number regex covering international, UK, Indian, US, and shortcode formats
PHONE_CANDIDATE_REGEX = re.compile(
    r"(?:"
    r"\+\d{1,3}[-.\s]?(?:\(?\d{2,5}\)?[-.\s]?)\d{3,5}[-.\s]?\d{3,6}\b"
    r"|\b\(?\d{3,5}\)?[-.\s]?\d{3,5}[-.\s]?\d{3,6}\b"
    r"|(?:\b|(?<=[a-zA-Z]))0\d{9,10}\b"
    r"|\b0\d{3,4}\s+\d{6,7}\b"
    r"|(?:\b|(?<=[a-zA-Z]))[6-9]\d{9}\b"  # Indian 10-digit mobile starting with 6, 7, 8, or 9
    r"|\b\d{5,6}\b"     # Common mobile SMS shortcodes (5-6 digits)
    r")"
)

# Patterns to filter out false positive phone matches (currency prefixes and unit suffixes)
CURRENCY_PREFIX_REGEX = re.compile(r"(?:[\$£€¥₹]|\bRs\.?|\bINR)\s*$", re.IGNORECASE)
UNIT_SUFFIX_REGEX = re.compile(
    r"^\s*(?:dollars?|rupees?|pounds?|euros?|inr|usd|gbp|eur|p|ppm|p/min|p/day|"
    r"hours?|mins?|minutes?|secs?|seconds?|days?|weeks?|months?|years?|points?|"
    r"am|pm|vouchers?|st|nd|rd|th|gb|mb|kb|km|miles)\b",
    re.IGNORECASE,
)


def extract_urls(text: str) -> List[str]:
    """Extracts URLs from text without network calls, domain resolution, or crawling.

    Args:
        text: Input string.

    Returns:
        List of cleaned, unvisited URL strings.
    """
    if not isinstance(text, str):
        return []
    urls = []
    for m in URL_REGEX.finditer(text):
        raw_url = m.group(0)
        # Strip trailing punctuation marks commonly adjacent to URLs in text
        clean = raw_url.rstrip(".,;!?'\")>]}")
        if clean:
            urls.append(clean)
    return urls


def extract_emails(text: str) -> List[str]:
    """Extracts email addresses from text deterministically.

    Args:
        text: Input string.

    Returns:
        List of email address strings.
    """
    if not isinstance(text, str):
        return []
    return [m.group(0) for m in EMAIL_REGEX.finditer(text)]


def extract_currencies(text: str) -> Tuple[List[str], List[float]]:
    """Extracts monetary mentions and parses numerical values.

    Args:
        text: Input string.

    Returns:
        Tuple of (currency_mentions list, parsed numeric amount values list).
    """
    if not isinstance(text, str):
        return [], []
    mentions: List[str] = []
    values: List[float] = []

    for m in CURRENCY_REGEX.finditer(text):
        raw_mention = m.group(0).strip()
        mentions.append(raw_mention)

        # Attempt safe numerical extraction
        num_match = re.search(r"\d+(?:,\d{3})*(?:\.\d+)?", raw_mention)
        if num_match:
            try:
                num_str = num_match.group(0).replace(",", "")
                val = float(num_str)
                # Check multiplier units with word boundaries to avoid substring collisions (e.g. 'k' in 'lakh')
                lower_mention = raw_mention.lower()
                if re.search(r"\bcrore\b", lower_mention):
                    val *= 10_000_000.0
                elif re.search(r"\blakh\b", lower_mention):
                    val *= 100_000.0
                elif re.search(r"\bmillion\b", lower_mention):
                    val *= 1_000_000.0
                elif re.search(r"\b(?:k)\b|\d+\s*k\b", lower_mention):
                    val *= 1000.0
                elif re.search(r"\b(?:m)\b|\d+\s*m\b", lower_mention) and not lower_mention.endswith("pm"):
                    val *= 1_000_000.0
                values.append(round(val, 2))
            except ValueError:
                pass

    return mentions, values


def extract_phone_numbers(
    text: str,
    urls: Optional[List[str]] = None,
    emails: Optional[List[str]] = None,
) -> List[str]:
    """Extracts candidate phone numbers and shortcodes while filtering out amounts and dates.

    Args:
        text: Input string.
        urls: Pre-extracted URLs to mask from text to avoid false positives.
        emails: Pre-extracted emails to mask from text.

    Returns:
        List of extracted phone number strings.
    """
    if not isinstance(text, str):
        return []

    # Mask URLs and emails to avoid extracting numbers from URLs/email handles
    masked_text = text
    if urls:
        for u in urls:
            masked_text = masked_text.replace(u, " " * len(u))
    if emails:
        for e in emails:
            masked_text = masked_text.replace(e, " " * len(e))

    candidates: List[str] = []

    for m in PHONE_CANDIDATE_REGEX.finditer(masked_text):
        raw_val = m.group(0).strip()
        clean_val = raw_val.rstrip(".,;!?'\")>]}")
        start, end = m.span()

        # Reject if preceded by currency symbols
        pre = masked_text[:start]
        if CURRENCY_PREFIX_REGEX.search(pre):
            continue

        # Reject if followed by units (e.g. dollars, points, years, hours)
        post = masked_text[end:]
        if UNIT_SUFFIX_REGEX.search(post):
            continue

        # Reject if part of a date, time, or decimal (e.g. 2026-10-02, 12.34, 10:30)
        # Only reject if adjacent component is a short 1-4 digit date component, not a full phone number
        if start > 0 and re.search(r"\b\d{1,4}[.:/-]$", masked_text[:start]):
            continue
        if end < len(masked_text) and re.match(r"^[.:/-]\d{1,4}\b", masked_text[end:]):
            continue

        # Clean digits-only count
        digits = re.sub(r"\D", "", clean_val)

        # For 5-6 digit shortcodes, reject round magnitude numbers (e.g. 10000, 20000)
        if len(digits) in (5, 6) and digits.endswith("000"):
            continue

        # Reject 4-digit numbers or fewer, or more than 15 digits
        if len(digits) < 5 or len(digits) > 15:
            continue

        candidates.append(clean_val)

    return candidates


def extract_all_entities(text: str) -> ExtractedEntities:
    """Extracts all entity classes from a message in a single deterministic pass.

    Args:
        text: Input string.

    Returns:
        ExtractedEntities dataclass populated with URLs, phones, emails, and currencies.
    """
    urls = extract_urls(text)
    emails = extract_emails(text)
    phone_numbers = extract_phone_numbers(text, urls=urls, emails=emails)
    currency_mentions, _ = extract_currencies(text)

    return ExtractedEntities(
        urls=urls,
        phone_numbers=phone_numbers,
        emails=emails,
        currency_mentions=currency_mentions,
    )
