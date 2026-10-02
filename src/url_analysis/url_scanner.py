"""Extracts and analyzes URLs for structural anomalies and evasion tactics.

OPERATIONAL SAFETY GUARANTEE:
- Zero outbound network requests.
- Zero DNS lookups or socket connections.
- Operates strictly on string syntax using Python standard libraries.
"""

from typing import List, Dict, Any, Optional
import re

from .analyzer import analyze_url
from .url_parser import parse_url
from ..preprocessing.extract_entities import extract_urls as deterministic_extract_urls


class URLScanner:
    """Offline scanner for passive URL extraction and structural risk analysis."""

    def extract_urls(self, text: str) -> List[str]:
        """Extracts candidate URLs from arbitrary text deterministically without network calls."""
        if not text:
            return []
        return deterministic_extract_urls(text)

    def analyze_url(self, url: str) -> Dict[str, Any]:
        """Analyzes a specific URL for structural properties and heuristic risk signals.

        Args:
            url: Candidate URL string.

        Returns:
            Structured dictionary of features, triggered signals, and risk score.
        """
        return analyze_url(url)
