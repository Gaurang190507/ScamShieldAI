"""Text normalization and span matching utilities for tactic detection.

Provides deterministic functions for locating regex patterns directly in the
original message string, ensuring 100% exact character offset alignment.
"""

from typing import List, Pattern, Tuple
import re


def find_pattern_spans(
    text: str,
    pattern: Pattern[str],
) -> List[Tuple[int, int, str]]:
    """Finds all non-overlapping matches for a compiled regex pattern in original text.

    Args:
        text: Original message text.
        pattern: Compiled regex pattern.

    Returns:
        List of tuples: (start_idx, end_idx, matched_substring).
    """
    spans: List[Tuple[int, int, str]] = []
    for match in pattern.finditer(text):
        start, end = match.span()
        matched_text = text[start:end]
        spans.append((start, end, matched_text))
    return spans


def is_contextually_negated(
    text: str,
    start: int,
    end: int,
    negative_pattern: Pattern[str],
    window: int = 50,
) -> bool:
    """Checks whether a matched span is negated by a nearby negative context pattern.

    Args:
        text: Original message string.
        start: Start offset of the candidate span.
        end: End offset of the candidate span.
        negative_pattern: Regex pattern indicating legitimate or non-deceptive context.
        window: Number of characters before and after the match to inspect.

    Returns:
        True if the negative pattern is matched within the local context window.
    """
    ctx_start = max(0, start - window)
    ctx_end = min(len(text), end + window)
    local_context = text[ctx_start:ctx_end]
    return bool(negative_pattern.search(local_context))
