"""URL analysis module: offline structural feature extraction and explainable threat heuristics.

OPERATIONAL SAFETY GUARANTEE:
- Zero outbound network requests.
- Zero DNS queries.
- Zero socket connections or HTTP clients.
"""

from .analyzer import analyze_url, URLAnalysisResult
from .url_parser import parse_url, ParsedURL
from .url_features import extract_url_features, URLFeatures
from .url_heuristics import evaluate_url_heuristics, URLHeuristicSignal
from .url_scanner import URLScanner

__all__ = [
    "analyze_url",
    "URLAnalysisResult",
    "parse_url",
    "ParsedURL",
    "extract_url_features",
    "URLFeatures",
    "evaluate_url_heuristics",
    "URLHeuristicSignal",
    "URLScanner",
]
