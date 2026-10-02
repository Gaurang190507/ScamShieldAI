"""Explainable heuristic risk signals and deterministic scoring for URL analysis.

OPERATIONAL SAFETY GUARANTEE:
- Zero outbound network requests.
- Zero DNS lookups or socket connections.
- Operates strictly on string syntax using Python standard libraries.
"""

from dataclasses import dataclass
from typing import Dict, Any, List, Tuple

from .url_parser import ParsedURL
from .url_features import URLFeatures


@dataclass
class URLHeuristicSignal:
    """Structured representation of a single triggered heuristic risk signal."""

    signal: str
    severity: str
    score: float
    evidence: str
    reason: str

    def to_dict(self) -> Dict[str, Any]:
        """Serializes signal to dictionary."""
        return {
            "signal": self.signal,
            "severity": self.severity,
            "score": round(self.score, 4),
            "evidence": self.evidence,
            "reason": self.reason,
        }


def _score_to_risk_level(score: float) -> str:
    """Maps a bounded heuristic risk score to a qualitative risk band.

    Engineering threshold bands:
        0.00 - 0.24 -> low
        0.25 - 0.49 -> moderate
        0.50 - 0.74 -> high
        0.75 - 1.00 -> very_high
    """
    if score >= 0.75:
        return "very_high"
    elif score >= 0.50:
        return "high"
    elif score >= 0.25:
        return "moderate"
    return "low"


def evaluate_url_heuristics(
    parsed: ParsedURL,
    features: URLFeatures,
) -> Tuple[List[URLHeuristicSignal], float, str]:
    """Evaluates explainable heuristic signals and computes an aggregate risk score.

    Avoids double-counting highly correlated features by applying dimensional
    ceilings across host, authority, scheme, path, query, and length properties.

    Args:
        parsed: ParsedURL instance.
        features: URLFeatures instance.

    Returns:
        Tuple of (signals_list, aggregate_risk_score, risk_level_string).
    """
    if not parsed.parse_success:
        signal = URLHeuristicSignal(
            signal="malformed_url",
            severity="low",
            score=0.0,
            evidence=parsed.error_message or "Unable to parse URL syntax",
            reason="The candidate string could not be parsed as a syntactically valid URL.",
        )
        return [signal], 0.0, "unknown"

    signals: List[URLHeuristicSignal] = []

    # Dimension score accumulators to prevent excessive correlation inflation
    dim_scheme = 0.0
    dim_host = 0.0
    dim_authority = 0.0
    dim_path = 0.0
    dim_query = 0.0
    dim_obfuscation = 0.0

    # 1. Unusual or Executable Scheme
    if features.has_unusual_scheme:
        sig = URLHeuristicSignal(
            signal="unusual_scheme",
            severity="high",
            score=0.35,
            evidence=f"Unusual or executable scheme detected: '{features.scheme}'",
            reason="The URL uses a non-standard or executable scheme which can bypass web security boundaries or execute unauthorized scripts.",
        )
        signals.append(sig)
        dim_scheme = max(dim_scheme, sig.score)

    # 2. Plain HTTP Scheme Analysis
    has_sensitive_context = bool(
        features.suspicious_path_keywords or features.suspicious_query_params
    )
    if features.is_http:
        if has_sensitive_context:
            sig = URLHeuristicSignal(
                signal="plain_http_sensitive",
                severity="medium",
                score=0.20,
                evidence=f"Insecure HTTP transport combined with sensitive keyword(s): {features.suspicious_path_keywords or features.suspicious_query_params}",
                reason="Authentication or financial actions requested over unencrypted plain HTTP transport expose user data to interception.",
            )
            signals.append(sig)
            dim_scheme = max(dim_scheme, sig.score)
        else:
            sig = URLHeuristicSignal(
                signal="insecure_http",
                severity="low",
                score=0.05,
                evidence="URL uses unencrypted 'http://' scheme",
                reason="The URL uses legacy unencrypted HTTP transport rather than modern HTTPS with TLS encryption.",
            )
            signals.append(sig)
            dim_scheme = max(dim_scheme, sig.score)

    # 3. Host Identity & IP-based Hostname
    if features.is_ip_hostname:
        ip_ver = "IPv4" if features.is_ipv4 else ("IPv6" if features.is_ipv6 else "IP")
        sig = URLHeuristicSignal(
            signal="ip_based_hostname",
            severity="medium",
            score=0.25,
            evidence=f"Hostname is an {ip_ver} address: '{features.hostname}'",
            reason="The URL points directly to an IP address instead of a registered domain name, commonly seen in transient attack infrastructure to evade domain reputation filters.",
        )
        signals.append(sig)
        dim_host += sig.score

    if features.has_punycode:
        sig = URLHeuristicSignal(
            signal="punycode_hostname",
            severity="medium",
            score=0.20,
            evidence=f"Hostname contains internationalized punycode label: '{features.hostname}'",
            reason="Hostname uses punycode encoding ('xn--'), which can be used in internationalized domain name (IDN) homograph attacks to mimic legitimate brands.",
        )
        signals.append(sig)
        dim_host += sig.score

    if features.has_non_ascii_hostname:
        sig = URLHeuristicSignal(
            signal="non_ascii_hostname",
            severity="low",
            score=0.10,
            evidence=f"Hostname contains non-ASCII characters: '{features.hostname}'",
            reason="Hostname contains non-ASCII characters outside the standard DNS alphanumeric range, requiring inspection for character spoofing.",
        )
        signals.append(sig)
        dim_host += sig.score

    # 4. Authority & Userinfo
    if features.has_userinfo:
        sig = URLHeuristicSignal(
            signal="userinfo_present",
            severity="high",
            score=0.30,
            evidence=f"Userinfo credentials embedded before host: '{features.userinfo}'",
            reason="The URL embeds credentials or misleading userinfo before the '@' sign, a classic visual spoofing technique to mislead users about the true destination host.",
        )
        signals.append(sig)
        dim_authority += sig.score

    if features.has_unusual_port:
        sig = URLHeuristicSignal(
            signal="unusual_port",
            severity="medium",
            score=0.20,
            evidence=f"Non-standard network port specified: {features.port}",
            reason="The URL targets a non-standard network port (not standard HTTP 80 or HTTPS 443), uncommon for legitimate consumer services.",
        )
        signals.append(sig)
        dim_authority += sig.score

    # 5. Path Structure & Keywords
    if features.suspicious_path_keywords:
        kw_count = len(features.suspicious_path_keywords)
        kw_score = 0.25 if kw_count >= 3 else 0.15
        kw_sev = "medium" if kw_count >= 3 else "low"
        sig = URLHeuristicSignal(
            signal="suspicious_path_keywords",
            severity=kw_sev,
            score=kw_score,
            evidence=f"Path contains sensitive keyword(s): {features.suspicious_path_keywords}",
            reason="Path contains authentication or financial transaction keywords frequently targeted by credential harvesting lures.",
        )
        signals.append(sig)
        dim_path += sig.score

    if features.percent_encoded_count >= 3:
        sig = URLHeuristicSignal(
            signal="excessive_percent_encoding",
            severity="low",
            score=0.10,
            evidence=f"{features.percent_encoded_count} percent-encoded sequences detected in path/query",
            reason="Multiple percent-encoded sequences (%xx) are present, which may obscure underlying characters or keywords from visual inspection.",
        )
        signals.append(sig)
        dim_path += sig.score

    # 6. Query Parameters & Redirect Indicators
    if features.suspicious_query_params:
        sig = URLHeuristicSignal(
            signal="suspicious_query_parameters",
            severity="low",
            score=0.15,
            evidence=f"Query string contains redirect/token parameter(s): {features.suspicious_query_params}",
            reason="Query string contains redirection or session-passing parameter keys which can facilitate open redirects or token leakage.",
        )
        signals.append(sig)
        dim_query += sig.score

    # 7. Obfuscation, Subdomains, Shorteners & Length
    if features.excessive_subdomain_depth:
        sig = URLHeuristicSignal(
            signal="excessive_subdomain_depth",
            severity="medium",
            score=0.20,
            evidence=f"Subdomain depth of {features.subdomain_count} levels: {features.subdomains}",
            reason="Hostname contains multiple nested subdomain levels, often used to simulate multi-layered legitimate domain structures on free or hijacked hosts.",
        )
        signals.append(sig)
        dim_obfuscation += sig.score

    if features.is_known_shortener:
        sig = URLHeuristicSignal(
            signal="known_shortener",
            severity="low",
            score=0.15,
            evidence=f"Host matches known URL shortening service: '{features.registered_domain or features.hostname}'",
            reason="The URL uses a known link-shortening service, obscuring the true destination hostname and path from initial visual inspection.",
        )
        signals.append(sig)
        dim_obfuscation += sig.score

    if features.is_excessive_url_length:
        sig = URLHeuristicSignal(
            signal="excessive_url_length",
            severity="low",
            score=0.10,
            evidence=f"Total URL length ({features.url_length} chars) exceeds threshold (120 chars)",
            reason="The URL is unusually long, which can be used to hide malicious parameters or overflow UI address bars.",
        )
        signals.append(sig)
        dim_obfuscation += sig.score

    # Apply dimension caps to prevent single structural aspects from inflating score
    capped_scheme = min(dim_scheme, 0.35)
    capped_host = min(dim_host, 0.35)
    capped_authority = min(dim_authority, 0.35)
    capped_path = min(dim_path, 0.30)
    capped_query = min(dim_query, 0.20)
    capped_obfuscation = min(dim_obfuscation, 0.30)

    # Compute aggregate heuristic score bounded in [0.0, 1.0]
    raw_aggregate = (
        capped_scheme
        + capped_host
        + capped_authority
        + capped_path
        + capped_query
        + capped_obfuscation
    )
    final_score = round(min(1.0, max(0.0, raw_aggregate)), 4)
    risk_level = _score_to_risk_level(final_score)

    return signals, final_score, risk_level
