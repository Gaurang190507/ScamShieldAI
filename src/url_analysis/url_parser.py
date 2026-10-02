"""Safe, deterministic URL parsing module operating exclusively offline.

OPERATIONAL SAFETY GUARANTEE:
- Zero outbound network requests.
- Zero DNS lookups or socket connections.
- Operates strictly on string syntax using Python standard libraries.
"""

from dataclasses import dataclass, field
import ipaddress
import re
from typing import Dict, Any, Optional
from urllib.parse import urlsplit


@dataclass
class ParsedURL:
    """Structured representation of parsed URL components."""

    raw_url: str
    parse_success: bool = True
    error_message: Optional[str] = None
    has_scheme: bool = False
    scheme: str = ""
    is_http: bool = False
    is_https: bool = False
    has_unusual_scheme: bool = False
    netloc: str = ""
    userinfo: str = ""
    has_userinfo: bool = False
    hostname: str = ""
    port: Optional[int] = None
    has_port: bool = False
    is_standard_port: bool = True
    path: str = ""
    query: str = ""
    fragment: str = ""

    def to_dict(self) -> Dict[str, Any]:
        """Converts parsed representation into a clean dictionary."""
        return {
            "raw_url": self.raw_url,
            "parse_success": self.parse_success,
            "error_message": self.error_message,
            "has_scheme": self.has_scheme,
            "scheme": self.scheme,
            "is_http": self.is_http,
            "is_https": self.is_https,
            "has_unusual_scheme": self.has_unusual_scheme,
            "netloc": self.netloc,
            "userinfo": self.userinfo,
            "has_userinfo": self.has_userinfo,
            "hostname": self.hostname,
            "port": self.port,
            "has_port": self.has_port,
            "is_standard_port": self.is_standard_port,
            "path": self.path,
            "query": self.query,
            "fragment": self.fragment,
        }


def _validate_host(host: str) -> bool:
    """Verifies that a candidate hostname has valid domain or IP structure."""
    if not host or any(c in host for c in (" ", "\t", "\n", "\r")):
        return False

    # IP address check
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        pass

    if host.lower() == "localhost":
        return True

    # Domain check: minimum 2 labels, valid label characters
    labels = host.split(".")
    if len(labels) < 2:
        return False

    for label in labels:
        if not label:
            return False
        # Allow alphanumeric, hyphens, underscores, punycode, or unicode letters
        if not re.match(r"^[a-zA-Z0-9_\-\u0080-\uffff]+$", label):
            return False

    return True


def parse_url(url: Any) -> ParsedURL:
    """Safely and deterministically parses an arbitrary URL string without network access.

    Handles explicit schemes (http, https), scheme-less domains/URLs (www.example.com,
    domain.com/path), IP-based hosts, non-standard ports, userinfo, and malformed inputs.

    Args:
        url: Input candidate URL string.

    Returns:
        ParsedURL dataclass instance with parsed components and validation status.
    """
    if not isinstance(url, str):
        return ParsedURL(
            raw_url=str(url) if url is not None else "",
            parse_success=False,
            error_message="Input must be a string",
        )

    raw_trimmed = url.strip()
    if not raw_trimmed:
        return ParsedURL(
            raw_url="",
            parse_success=False,
            error_message="URL string is empty",
        )

    # Detect unusual schemes like javascript:, data:, file:, etc.
    scheme_match = re.match(r"^([a-zA-Z][a-zA-Z0-9+.-]*):(?:/{0,3})", raw_trimmed)
    explicit_scheme = ""
    has_scheme = False

    if scheme_match:
        explicit_scheme = scheme_match.group(1).lower()
        has_scheme = True

    # Handle dangerous/unusual pseudo-schemes
    unusual_schemes = {"javascript", "data", "vbscript", "file", "blob", "about"}
    if explicit_scheme in unusual_schemes:
        return ParsedURL(
            raw_url=raw_trimmed,
            parse_success=True,
            has_scheme=True,
            scheme=explicit_scheme,
            has_unusual_scheme=True,
            path=raw_trimmed[scheme_match.end() :],
        )

    # For standard web URLs or scheme-less URLs
    url_to_split = raw_trimmed if has_scheme else f"http://{raw_trimmed}"

    try:
        split_result = urlsplit(url_to_split)
    except Exception as e:
        return ParsedURL(
            raw_url=raw_trimmed,
            parse_success=False,
            error_message=f"Syntax parsing failure: {str(e)}",
        )

    netloc = split_result.netloc
    userinfo = ""
    if "@" in netloc:
        userinfo, _ = netloc.rsplit("@", 1)

    try:
        raw_hostname = split_result.hostname or ""
        port = split_result.port
    except ValueError as e:
        return ParsedURL(
            raw_url=raw_trimmed,
            parse_success=False,
            error_message=f"Malformed port specification: {str(e)}",
        )

    scheme_val = explicit_scheme if has_scheme else ""
    is_http = scheme_val == "http"
    is_https = scheme_val == "https"
    has_unusual = has_scheme and (scheme_val not in {"http", "https", "ftp", "mailto", "tel", "sms"})

    # Host validation: web and scheme-less URLs require a valid non-empty host
    hostname_clean = raw_hostname.lower()
    if is_http or is_https or not has_scheme:
        if not hostname_clean or not _validate_host(hostname_clean):
            return ParsedURL(
                raw_url=raw_trimmed,
                parse_success=False,
                error_message=f"Missing or invalid host: '{raw_hostname}'",
            )

    # Determine if port is standard
    has_port = port is not None
    is_std_port = True
    if has_port:
        if is_http and port == 80:
            is_std_port = True
        elif is_https and port == 443:
            is_std_port = True
        elif not has_scheme and port in {80, 443}:
            is_std_port = True
        else:
            is_std_port = False

    return ParsedURL(
        raw_url=raw_trimmed,
        parse_success=True,
        error_message=None,
        has_scheme=has_scheme,
        scheme=scheme_val,
        is_http=is_http,
        is_https=is_https,
        has_unusual_scheme=has_unusual,
        netloc=netloc,
        userinfo=userinfo,
        has_userinfo=bool(userinfo),
        hostname=hostname_clean,
        port=port,
        has_port=has_port,
        is_standard_port=is_std_port,
        path=split_result.path,
        query=split_result.query,
        fragment=split_result.fragment,
    )
