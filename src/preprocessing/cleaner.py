"""Text normalization and preprocessing utilities."""

from typing import Dict, Any
import re


def clean_text(text: str) -> str:
    """Basic text cleanup preserving behavioral indicators (e.g., punctuation, capitalization).

    Args:
        text: Raw input text from message, email, or post.

    Returns:
        Cleaned text string.
    """
    if not isinstance(text, str):
        return ""
    # Normalize excessive whitespace while preserving raw sentence context
    normalized = re.sub(r"[ \t]+", " ", text)
    return normalized.strip()
