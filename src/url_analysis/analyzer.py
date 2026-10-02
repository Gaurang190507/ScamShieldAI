"""Unified entry point for passive, offline URL risk analysis.

OPERATIONAL SAFETY GUARANTEE:
- Zero outbound network requests.
- Zero DNS lookups or socket connections.
- Operates strictly on string syntax using Python standard libraries.
"""

from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, Any, List, Optional

from .url_parser import parse_url, ParsedURL
from .url_features import extract_url_features, URLFeatures
from .url_heuristics import evaluate_url_heuristics, URLHeuristicSignal


@dataclass
class URLAnalysisResult:
    """Structured result of passive URL risk analysis."""

    url: str
    parse_success: bool
    features: Dict[str, Any]
    signals: List[Dict[str, Any]]
    risk_score: float
    risk_level: str
    error_message: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        """Serializes result to standard dictionary."""
        return {
            "url": self.url,
            "parse_success": self.parse_success,
            "error_message": self.error_message,
            "features": self.features,
            "signals": self.signals,
            "risk_score": self.risk_score,
            "risk_level": self.risk_level,
        }


def analyze_url(
    url: Any,
    shorteners_config: Optional[Path] = None,
) -> Dict[str, Any]:
    """Analyzes a URL string purely through passive offline structural heuristics.

    Does NOT contact the network, query DNS, or verify domain existence.

    Args:
        url: Candidate URL string.
        shorteners_config: Optional path to custom shorteners JSON configuration.

    Returns:
        Structured dictionary matching Phase 4 output contract:
        - url: original input string
        - parse_success: boolean
        - error_message: string if parse failed, else None
        - features: dictionary of structural features
        - signals: list of triggered heuristic signals with evidence and reason
        - risk_score: float in [0.0, 1.0]
        - risk_level: 'low', 'moderate', 'high', 'very_high', or 'unknown'
    """
    parsed: ParsedURL = parse_url(url)

    if not parsed.parse_success:
        dummy_features = URLFeatures(
            url_length=len(str(url)) if url is not None else 0
        )
        signals, score, level = evaluate_url_heuristics(parsed, dummy_features)
        return URLAnalysisResult(
            url=str(url) if url is not None else "",
            parse_success=False,
            error_message=parsed.error_message,
            features=dummy_features.to_dict(),
            signals=[s.to_dict() for s in signals],
            risk_score=score,
            risk_level=level,
        ).to_dict()

    features: URLFeatures = extract_url_features(
        parsed, shorteners_config=shorteners_config
    )
    signals, score, level = evaluate_url_heuristics(parsed, features)

    return URLAnalysisResult(
        url=parsed.raw_url,
        parse_success=True,
        error_message=None,
        features=features.to_dict(),
        signals=[s.to_dict() for s in signals],
        risk_score=score,
        risk_level=level,
    ).to_dict()
