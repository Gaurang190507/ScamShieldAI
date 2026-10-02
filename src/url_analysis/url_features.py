"""Deterministic structural URL feature extraction.

OPERATIONAL SAFETY GUARANTEE:
- Zero outbound network requests.
- Zero DNS lookups or socket connections.
- Operates strictly on string syntax using Python standard libraries.
"""

from dataclasses import dataclass, field
import ipaddress
import json
from pathlib import Path
import re
from typing import Dict, Any, List, Optional, Set
from urllib.parse import parse_qs

from .url_parser import ParsedURL


# Documented transparent thresholds
EXCESSIVE_URL_LENGTH_THRESHOLD = 120
EXCESSIVE_HOSTNAME_LENGTH_THRESHOLD = 50
EXCESSIVE_PATH_LENGTH_THRESHOLD = 75
EXCESSIVE_SUBDOMAIN_DEPTH_THRESHOLD = 3
EXCESSIVE_PERCENT_ENCODING_THRESHOLD = 3

# Documented structural term lists (contextual/structural signals only, NOT scam labels)
SUSPICIOUS_PATH_KEYWORDS = (
    "login",
    "verify",
    "verification",
    "secure",
    "account",
    "update",
    "confirm",
    "payment",
    "refund",
    "kyc",
    "wallet",
    "support",
    "billing",
    "authenticate",
    "banking",
    "signin",
    "re-activate",
)

SUSPICIOUS_QUERY_PARAMS = (
    "redirect",
    "url",
    "next",
    "return",
    "continue",
    "token",
    "session",
    "auth",
    "verify",
    "goto",
    "dest",
    "target",
    "link",
)

# Common 2-part ccTLDs for domain segmentation
TWO_PART_CCTLDS = {
    "co.uk", "gov.uk", "ac.uk", "org.uk", "ltd.uk",
    "co.in", "gov.in", "ac.in", "org.in", "net.in", "nic.in", "res.in",
    "com.au", "net.au", "org.au", "edu.au", "gov.au",
    "co.nz", "net.nz", "org.nz", "govt.nz",
    "co.za", "org.za", "gov.za",
    "com.sg", "edu.sg", "gov.sg", "org.sg",
}


def _load_known_shorteners(config_path: Optional[Path] = None) -> Set[str]:
    """Loads configured known shortening service domains from disk."""
    if config_path is None:
        config_path = Path(__file__).resolve().parent / "known_shorteners.json"
    if config_path.is_file():
        try:
            with open(config_path, "r", encoding="utf-8") as f:
                return set(json.load(f))
        except Exception:
            pass
    # Fallback default set if file is unreadable
    return {
        "bit.ly", "tinyurl.com", "t.co", "goo.gl", "is.gd", "ow.ly",
        "buff.ly", "rebrand.ly", "clck.ru", "tiny.cc", "s.id", "cutt.ly",
    }


@dataclass
class URLFeatures:
    """Comprehensive structural feature vector extracted deterministically from a URL."""

    # Scheme
    has_scheme: bool = False
    scheme: str = ""
    is_http: bool = False
    is_https: bool = False
    has_unusual_scheme: bool = False

    # Host
    hostname: str = ""
    hostname_length: int = 0
    hostname_labels_count: int = 0
    subdomains: List[str] = field(default_factory=list)
    subdomain_count: int = 0
    excessive_subdomain_depth: bool = False
    registered_domain: str = ""
    tld: str = ""
    tld_length: int = 0
    is_ip_hostname: bool = False
    is_ipv4: bool = False
    is_ipv6: bool = False
    has_punycode: bool = False
    has_non_ascii_hostname: bool = False

    # Port
    has_port: bool = False
    port: Optional[int] = None
    has_unusual_port: bool = False

    # Userinfo
    has_userinfo: bool = False
    userinfo: str = ""

    # Path
    path: str = ""
    path_length: int = 0
    path_depth: int = 0
    path_segments_count: int = 0
    special_character_count: int = 0
    percent_encoded_count: int = 0
    suspicious_path_keywords: List[str] = field(default_factory=list)

    # Query
    query: str = ""
    query_length: int = 0
    query_params_count: int = 0
    ampersand_count: int = 0
    equal_count: int = 0
    suspicious_query_params: List[str] = field(default_factory=list)

    # Lengths & thresholds
    url_length: int = 0
    is_excessive_url_length: bool = False
    is_excessive_hostname_length: bool = False
    is_excessive_path_length: bool = False

    # Shorteners
    is_known_shortener: bool = False

    def to_dict(self) -> Dict[str, Any]:
        """Serializes features to standard dictionary."""
        return {
            "has_scheme": self.has_scheme,
            "scheme": self.scheme,
            "is_http": self.is_http,
            "is_https": self.is_https,
            "has_unusual_scheme": self.has_unusual_scheme,
            "hostname": self.hostname,
            "hostname_length": self.hostname_length,
            "hostname_labels_count": self.hostname_labels_count,
            "subdomains": self.subdomains,
            "subdomain_count": self.subdomain_count,
            "excessive_subdomain_depth": self.excessive_subdomain_depth,
            "registered_domain": self.registered_domain,
            "tld": self.tld,
            "tld_length": self.tld_length,
            "is_ip_hostname": self.is_ip_hostname,
            "is_ipv4": self.is_ipv4,
            "is_ipv6": self.is_ipv6,
            "has_punycode": self.has_punycode,
            "has_non_ascii_hostname": self.has_non_ascii_hostname,
            "has_port": self.has_port,
            "port": self.port,
            "has_unusual_port": self.has_unusual_port,
            "has_userinfo": self.has_userinfo,
            "userinfo": self.userinfo,
            "path_length": self.path_length,
            "path_depth": self.path_depth,
            "path_segments_count": self.path_segments_count,
            "special_character_count": self.special_character_count,
            "percent_encoded_count": self.percent_encoded_count,
            "suspicious_path_keywords": self.suspicious_path_keywords,
            "query_length": self.query_length,
            "query_params_count": self.query_params_count,
            "ampersand_count": self.ampersand_count,
            "equal_count": self.equal_count,
            "suspicious_query_params": self.suspicious_query_params,
            "url_length": self.url_length,
            "is_excessive_url_length": self.is_excessive_url_length,
            "is_excessive_hostname_length": self.is_excessive_hostname_length,
            "is_excessive_path_length": self.is_excessive_path_length,
            "is_known_shortener": self.is_known_shortener,
        }


def extract_url_features(
    parsed: ParsedURL,
    shorteners_config: Optional[Path] = None,
) -> URLFeatures:
    """Extracts deterministic structural features from a parsed URL.

    Args:
        parsed: ParsedURL instance from url_parser.
        shorteners_config: Optional custom path to shorteners JSON.

    Returns:
        Populated URLFeatures dataclass instance.
    """
    raw_url = parsed.raw_url
    url_len = len(raw_url)
    hostname = parsed.hostname

    # 1. Host Analysis & IP Detection
    is_ip = False
    is_ipv4 = False
    is_ipv6 = False
    try:
        ip_obj = ipaddress.ip_address(hostname)
        is_ip = True
        is_ipv4 = ip_obj.version == 4
        is_ipv6 = ip_obj.version == 6
    except ValueError:
        pass

    has_puny = False
    has_non_ascii = any(ord(c) > 127 for c in hostname)
    labels = hostname.split(".") if hostname else []
    labels_count = len(labels) if hostname else 0

    subdomains: List[str] = []
    reg_domain = ""
    tld = ""

    if is_ip:
        reg_domain = hostname
        tld = ""
    elif labels_count >= 2:
        # Check for 2-part ccTLDs
        if labels_count >= 3 and f"{labels[-2]}.{labels[-1]}" in TWO_PART_CCTLDS:
            tld = f"{labels[-2]}.{labels[-1]}"
            reg_domain = f"{labels[-3]}.{tld}"
            subdomains = labels[:-3]
        else:
            tld = labels[-1]
            reg_domain = f"{labels[-2]}.{tld}"
            subdomains = labels[:-2]

        # Check for punycode in any label
        for lab in labels:
            if lab.startswith("xn--"):
                has_puny = True
    elif labels_count == 1:
        reg_domain = hostname
        tld = ""

    # Normalize subdomains (filter out empty labels)
    subdomains = [s for s in subdomains if s]
    subdomain_count = len(subdomains)
    excessive_subdomains = subdomain_count >= EXCESSIVE_SUBDOMAIN_DEPTH_THRESHOLD

    # 2. Port Analysis
    has_unusual_port = not parsed.is_standard_port if parsed.has_port else False

    # 3. Path Analysis
    path = parsed.path
    path_len = len(path)
    segments = [seg for seg in path.split("/") if seg]
    path_depth = len(segments)

    # Percent encoding count in path + query
    full_path_query = f"{path}?{parsed.query}" if parsed.query else path
    percent_enc_matches = re.findall(r"%[0-9a-fA-F]{2}", full_path_query)
    percent_enc_count = len(percent_enc_matches)

    # Special characters in path (characters beyond alphanumeric, standard separators)
    special_chars = re.findall(r"[^a-zA-Z0-9/._\-~%]", path)
    special_char_count = len(special_chars)

    # Suspicious path keywords
    path_lower = path.lower()
    matched_path_keywords = [
        kw for kw in SUSPICIOUS_PATH_KEYWORDS
        if re.search(rf"\b{re.escape(kw)}\b", path_lower) or f"/{kw}" in path_lower or f"-{kw}" in path_lower
    ]

    # 4. Query Analysis
    query = parsed.query
    query_len = len(query)
    amp_count = query.count("&")
    eq_count = query.count("=")
    query_params_count = 0
    matched_query_params: List[str] = []

    if query:
        try:
            parsed_params = parse_qs(query, keep_blank_values=True)
            query_params_count = len(parsed_params)
            for param_key in parsed_params.keys():
                param_lower = param_key.lower()
                for sus_param in SUSPICIOUS_QUERY_PARAMS:
                    if sus_param in param_lower:
                        matched_query_params.append(param_lower)
                        break
        except Exception:
            # Fallback for irregular queries
            query_params_count = eq_count

    # 5. Length Thresholds
    is_excessive_url = url_len > EXCESSIVE_URL_LENGTH_THRESHOLD
    is_excessive_host = len(hostname) > EXCESSIVE_HOSTNAME_LENGTH_THRESHOLD
    is_excessive_path = path_len > EXCESSIVE_PATH_LENGTH_THRESHOLD

    # 6. Shortener Detection
    known_shorteners = _load_known_shorteners(shorteners_config)
    is_shortener = reg_domain.lower() in known_shorteners or hostname.lower() in known_shorteners

    return URLFeatures(
        has_scheme=parsed.has_scheme,
        scheme=parsed.scheme,
        is_http=parsed.is_http,
        is_https=parsed.is_https,
        has_unusual_scheme=parsed.has_unusual_scheme,
        hostname=hostname,
        hostname_length=len(hostname),
        hostname_labels_count=labels_count,
        subdomains=subdomains,
        subdomain_count=subdomain_count,
        excessive_subdomain_depth=excessive_subdomains,
        registered_domain=reg_domain,
        tld=tld,
        tld_length=len(tld),
        is_ip_hostname=is_ip,
        is_ipv4=is_ipv4,
        is_ipv6=is_ipv6,
        has_punycode=has_puny,
        has_non_ascii_hostname=has_non_ascii,
        has_port=parsed.has_port,
        port=parsed.port,
        has_unusual_port=has_unusual_port,
        has_userinfo=parsed.has_userinfo,
        userinfo=parsed.userinfo,
        path=path,
        path_length=path_len,
        path_depth=path_depth,
        path_segments_count=len(segments),
        special_character_count=special_char_count,
        percent_encoded_count=percent_enc_count,
        suspicious_path_keywords=matched_path_keywords,
        query=query,
        query_length=query_len,
        query_params_count=query_params_count,
        ampersand_count=amp_count,
        equal_count=eq_count,
        suspicious_query_params=matched_query_params,
        url_length=url_len,
        is_excessive_url_length=is_excessive_url,
        is_excessive_hostname_length=is_excessive_host,
        is_excessive_path_length=is_excessive_path,
        is_known_shortener=is_shortener,
    )
