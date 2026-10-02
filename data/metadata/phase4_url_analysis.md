# Phase 4 Passive URL Analysis & Threat Heuristics Specification 🔗

**Component:** ScamShield AI Passive URL Analysis Engine  
**Operational Scope:** 100% Offline, Deterministic URL String Analysis  
**Security Boundary:** **Zero outbound network requests are made.** No DNS queries, WHOIS lookups, socket connections, HTTP requests, or external APIs.

---

## 1. Objective

The objective of Phase 4 is to establish an offline, deterministic structural URL analysis and threat heuristic component for ScamShield AI.

Rather than attempting to make a premature binary classification (*"Is this definitely a scam?"*), this component evaluates:
> *"What suspicious structural characteristics and evasion techniques does this candidate URL contain?"*

It extracts concrete structural features, fires explainable heuristic signals with detailed evidence and reasons, and produces a bounded heuristic risk score that will subsequently serve as an evidence layer for ScamShield's unified multi-modal risk engine.

---

## 2. Input Specification

- **Input Format:** Raw URL string only (`str`).
- **Input Scope:** Web URLs (`https://`, `http://`), scheme-less links (`www.domain.com/path`, `domain.com`), IP-based addresses (`http://192.168.1.1/login`), non-standard ports, userinfo, and candidate substrings extracted from messages.
- **Handling of Malformed Input:** Non-strings, empty inputs, whitespace, broken syntax, or unparseable URLs are handled gracefully without exceptions, returning `parse_success = False` and `risk_score = 0.0`.

---

## 3. Parsing Architecture

Implemented in [`src/url_analysis/url_parser.py`](file:///c:/Users/radika/OneDrive/Desktop/ScamShieldAI/src/url_analysis/url_parser.py) via Python's standard `urllib.parse` and `ipaddress`:
1. **Sanitization:** Trims whitespace and inspects candidate schemes.
2. **Unusual / Executable Schemes:** Detects non-web schemes (e.g. `javascript:`, `data:`, `file:`) and tags them with `has_unusual_scheme = True`.
3. **Scheme-less Normalization:** Prepends internal `http://` for parsing if no scheme is specified, while recording `has_scheme = False`.
4. **Authority Separation:** Disassembles netloc into `userinfo` (if `@` exists), `hostname`, and `port`.
5. **Host Validation:** Verifies candidate hostnames against standard IP and domain label syntax to reject random non-URL text artifacts.
6. **Output:** Returns [`ParsedURL`](file:///c:/Users/radika/OneDrive/Desktop/ScamShieldAI/src/url_analysis/url_parser.py#L13) containing `raw_url`, `parse_success`, `scheme`, `hostname`, `port`, `userinfo`, `path`, `query`, and `fragment`.

---

## 4. Extracted Structural Features

Implemented in [`src/url_analysis/url_features.py`](file:///c:/Users/radika/OneDrive/Desktop/ScamShieldAI/src/url_analysis/url_features.py):

| Category | Feature Name | Type | Description |
| :--- | :--- | :---: | :--- |
| **Scheme** | `has_scheme` | `bool` | Whether an explicit protocol scheme was provided. |
| | `scheme` | `str` | Normalized lowercase scheme (e.g., `https`, `http`). |
| | `is_http` | `bool` | True if scheme is unencrypted `http`. |
| | `is_https` | `bool` | True if scheme is encrypted `https`. |
| | `has_unusual_scheme` | `bool` | True if scheme is non-standard/executable (`javascript`, `data`, `file`). |
| **Host** | `hostname` | `str` | Lowercase hostname or IP address. |
| | `hostname_length` | `int` | Character length of the host string. |
| | `hostname_labels_count`| `int` | Total period-separated labels in host. |
| | `subdomains` | `list` | Extracted subdomain prefixes (excluding registered domain & TLD). |
| | `subdomain_count` | `int` | Total nested subdomain levels. |
| | `excessive_subdomain_depth`| `bool` | True if subdomain depth >= 3. |
| | `registered_domain` | `str` | Segmented base domain (accounting for 2-part ccTLDs like `.co.in`, `.co.uk`). |
| | `tld` | `str` | Top-level domain string. |
| | `tld_length` | `int` | Character length of the TLD. |
| | `is_ip_hostname` | `bool` | True if host is a numeric IP address. |
| | `is_ipv4` | `bool` | True if host is an IPv4 address. |
| | `is_ipv6` | `bool` | True if host is an IPv6 address. |
| | `has_punycode` | `bool` | True if any label begins with `xn--`. |
| | `has_non_ascii_hostname` | `bool` | True if host contains non-ASCII characters. |
| **Port** | `has_port` | `bool` | True if explicit network port is present. |
| | `port` | `int` | Extracted port number. |
| | `has_unusual_port` | `bool` | True if port is not standard 80 or 443. |
| **Authority**| `has_userinfo` | `bool` | True if credentials or userinfo exist before `@`. |
| | `userinfo` | `str` | Extracted userinfo string. |
| **Path** | `path` | `str` | URL path component. |
| | `path_length` | `int` | Character length of the path string. |
| | `path_depth` | `int` | Number of non-empty slash-delimited segments. |
| | `path_segments_count` | `int` | Total segment count. |
| | `special_character_count` | `int` | Count of characters outside alphanumeric/standard separators. |
| | `percent_encoded_count` | `int` | Count of `%xx` hex escape sequences. |
| | `suspicious_path_keywords` | `list` | Matched authentication/financial terms (`login`, `verify`, `kyc`, etc.). |
| **Query** | `query` | `str` | Raw query parameter string. |
| | `query_length` | `int` | Character length of the query. |
| | `query_params_count` | `int` | Total parsed key-value parameters. |
| | `ampersand_count` | `int` | Count of `&` characters. |
| | `equal_count` | `int` | Count of `=` characters. |
| | `suspicious_query_params` | `list` | Matched redirect/token parameters (`redirect`, `token`, `next`, etc.). |
| **Length** | `url_length` | `int` | Total string length. |
| | `is_excessive_url_length` | `bool` | True if total URL length > 120 characters. |
| | `is_excessive_hostname_length`| `bool` | True if hostname > 50 characters. |
| | `is_excessive_path_length` | `bool` | True if path length > 75 characters. |
| **Shortener**| `is_known_shortener` | `bool` | True if host matches documented shortener configuration. |

---

## 5. Explainable Threat Heuristics Catalog

Implemented in [`src/url_analysis/url_heuristics.py`](file:///c:/Users/radika/OneDrive/Desktop/ScamShieldAI/src/url_analysis/url_heuristics.py):

Each triggered signal generates a structured record:
```json
{
  "signal": "string_identifier",
  "severity": "low | medium | high",
  "score": 0.05 - 0.35,
  "evidence": "Concrete substring or parameter found",
  "reason": "Human-readable explanation of risk"
}
```

### Signal Specifications

#### 1. `unusual_scheme`
- **Meaning:** URL uses an executable or non-standard protocol scheme (e.g., `javascript:`, `data:`, `file:`).
- **Severity:** `high`
- **Score Contribution:** `0.35`
- **Limitations:** Legitimate bookmarklets or data URIs can trigger this, but in inbound communication links they represent severe XSS/execution hazards.

#### 2. `userinfo_present`
- **Meaning:** The URL embeds user credentials or decorative identifiers before the `@` symbol (e.g., `https://support@paypal.com@evil.com/`).
- **Severity:** `high`
- **Score Contribution:** `0.30`
- **Limitations:** Legitimate internal development URLs occasionally use basic auth, but public links with userinfo are almost universally deceptive visual homographs.

#### 3. `ip_based_hostname`
- **Meaning:** Host is a numeric IPv4 or IPv6 address rather than a domain name.
- **Severity:** `medium`
- **Score Contribution:** `0.25`
- **Limitations:** Local router admin interfaces (`192.168.1.1`) or direct API servers use IP addresses. However, consumer-facing phishing frequently hosts temporary pages on raw VPS IPs.

#### 4. `plain_http_sensitive`
- **Meaning:** Insecure unencrypted `http://` transport combined with sensitive authentication or financial keywords (`login`, `verify`, `account`, `kyc`).
- **Severity:** `medium`
- **Score Contribution:** `0.20`
- **Limitations:** Legacy non-HTTPS sites may exist, but requesting credentials or financial verification over plain HTTP violates security standards and exposes victims to MITM interception.

#### 5. `unusual_port`
- **Meaning:** Target host specifies a non-standard network port (other than 80 or 443).
- **Severity:** `medium`
- **Score Contribution:** `0.20`
- **Limitations:** Internal enterprise and development systems use ports like 8080 or 8443; consumer-facing legitimate public services rarely do.

#### 6. `excessive_subdomain_depth`
- **Meaning:** Hostname contains 3 or more nested subdomain levels (e.g., `login.account.security.verify.example.com`).
- **Severity:** `medium`
- **Score Contribution:** `0.20`
- **Limitations:** Complex enterprise CDN or multi-tenant architectures use deep subdomains. Phishing campaigns frequently deploy deep subdomains on free hosting providers (e.g. DuckDNS, Cloudflare tunnels) to simulate brand hierarchies.

#### 7. `punycode_hostname`
- **Meaning:** Hostname label uses internationalized domain name (IDN) punycode prefix (`xn--`).
- **Severity:** `medium`
- **Score Contribution:** `0.20`
- **Limitations:** Legitimate non-Latin websites in Cyrillic, Chinese, Arabic, or Devanagari use punycode. In Latin-predominant corpora, punycode is frequently employed for visually deceptive homoglyph attacks (e.g. Cyrillic `а` mimicking Latin `a`).

#### 8. `suspicious_path_keywords`
- **Meaning:** Path contains sensitive credential or transaction terms (`login`, `verify`, `kyc`, `refund`, `wallet`).
- **Severity:** `low` (1-2 keywords, score `0.15`) or `medium` (>=3 keywords, score `0.25`).
- **Score Contribution:** `0.15` - `0.25`
- **Limitations:** Legitimate login portals naturally contain the word `login`. This signal is purely contextual and carries low individual weight unless combined with untrusted host or transport signals.

#### 9. `suspicious_query_parameters`
- **Meaning:** Query string includes open-redirect or authentication-passing parameter keys (`redirect`, `token`, `next`, `url`).
- **Severity:** `low`
- **Score Contribution:** `0.15`
- **Limitations:** Legitimate SSO workflows and web apps utilize `redirect` and `token` parameters. It represents an architectural vulnerability surface rather than definitive malice.

#### 10. `known_shortener`
- **Meaning:** Host belongs to a documented public link shortening service (e.g., `bit.ly`, `tinyurl.com`, `t.co`).
- **Severity:** `low`
- **Score Contribution:** `0.15`
- **Limitations:** URL shorteners are ubiquitously used by legitimate marketers and social media platforms. The signal reflects intentional destination opacity, not malice.

#### 11. `non_ascii_hostname`
- **Meaning:** Hostname contains non-ASCII characters outside standard DNS alphanumeric range.
- **Severity:** `low`
- **Score Contribution:** `0.10`
- **Limitations:** Internationalized domain names legitimately serve non-English speakers worldwide.

#### 12. `excessive_url_length`
- **Meaning:** Total URL length exceeds 120 characters.
- **Severity:** `low`
- **Score Contribution:** `0.10`
- **Limitations:** Legitimate referral and marketing links with multiple tracking parameters frequently exceed 120 characters.

#### 13. `excessive_percent_encoding`
- **Meaning:** 3 or more percent-encoded hex sequences (`%xx`) in path or query.
- **Severity:** `low`
- **Score Contribution:** `0.10`
- **Limitations:** Legitimate search queries with spaces and symbols contain percent encoding.

#### 14. `insecure_http`
- **Meaning:** URL uses plain `http://` transport without sensitive authentication keywords.
- **Severity:** `low`
- **Score Contribution:** `0.05`
- **Limitations:** Many informational, read-only blogs and websites still serve static content over plain HTTP.

---

## 6. Heuristic Scoring & Dimensional Capping

The heuristic risk score is **NOT a probability of fraud**. It is an engineering index reflecting the cumulative presence of structural risk signals.

### Anti-Correlation Dimensional Caps
To prevent a single structural attribute (such as long path length coupled with multiple path keywords and percent encoding) from inflating the score artificially, dimensional caps are enforced:

- **Host Identity Dimension** (`ip_based_hostname`, `punycode_hostname`, `non_ascii_hostname`): Capped at `0.35`
- **Authority / Credentials Dimension** (`userinfo_present`, `unusual_port`): Capped at `0.35`
- **Scheme Dimension** (`unusual_scheme`, `plain_http_sensitive`, `insecure_http`): Capped at `0.35`
- **Path Content Dimension** (`suspicious_path_keywords`, `excessive_percent_encoding`): Capped at `0.30`
- **Query / Redirection Dimension** (`suspicious_query_params`): Capped at `0.20`
- **Obfuscation / Length Dimension** (`known_shortener`, `excessive_subdomain_depth`, `excessive_url_length`): Capped at `0.30`

### Aggregate Score & Qualitative Bands:
$$\text{Score} = \min\left(1.0, \sum \text{Capped Dimensions}\right)$$

| Score Range | Qualitative Risk Level | Interpretation |
| :---: | :---: | :--- |
| **0.00 – 0.24** | `low` | Standard structural syntax; minimal or benign anomalies. |
| **0.25 – 0.49** | `moderate` | Single moderate risk indicator or minor compounding flags. |
| **0.50 – 0.74** | `high` | Multiple compounding risk signals (e.g. IP host + sensitive path). |
| **0.75 – 1.00** | `very_high` | Multiple severe compounding signals (e.g. userinfo + unusual port + IP host). |

---

## 7. Principle of No Single-Signal Verdict

The URL analyzer **never** emits a boolean `malicious = True` or `is_scam = True` verdict.

A URL will never be deemed fraudulent solely because:
- It uses unencrypted HTTP
- It points to an IP address
- It uses a URL shortener
- It contains the word `login` or `verify`
- It is hosted on a non-standard port

All outputs are structured as **evidence signals** intended to be weighed alongside text classification, tactic extraction, and semantic analysis in future phases.

---

## 8. Corpus Analysis (UCI SMS Spam Collection)

Batch analysis of the 5,574-record UCI dataset was executed via [`src/url_analysis/analyze_dataset_urls.py`](file:///c:/Users/radika/OneDrive/Desktop/ScamShieldAI/src/url_analysis/analyze_dataset_urls.py) and serialized to [`data/evaluation/url_analysis/`](file:///c:/Users/radika/OneDrive/Desktop/ScamShieldAI/data/evaluation/url_analysis):

### Findings:
- **Total Messages Analyzed:** `5,574`
- **Messages Containing Extracted URLs:** `108` (`1.94%`)
- **Total URL Mentions:** `108`
- **Unique URLs Extracted:** `67`
- **Malformed / Corrupted URL Mentions:** `2` (e.g., carrier billing artifacts concatenated into URLs: `www.Ldew.com.subs16+1win150ppmx3`)
- **Schemes Distribution:**
  - `no_scheme` (`www...`): `86` mentions (79.6%)
  - `http://`: `20` mentions (18.5%)
  - `https://`: `0` mentions (0.0% — historical 2011 dataset predates universal HTTPS migration)
- **Host Indicators in UCI:**
  - `ip_based_hostnames`: `0`
  - `punycode_hostnames`: `0`
  - `known_shorteners`: `0`
- **Risk Score Distribution in UCI:**
  - `low` (`[0.00, 0.24]`): `106` mentions (98.15%)
  - `unknown` (malformed text): `2` mentions (1.85%)
  - Mean score: `0.0093`
  - Max score: `0.05`

*Note on Unsupervised Evaluation:* Class labels (`scam`/`non_scam`) were strictly omitted from heuristic score formulation to prevent calibration bias.

---

## 9. False-Positive Considerations

Legitimate URLs frequently exhibit structural properties that overlap with threat techniques:
1. **Link Shorteners (`bit.ly`, `tinyurl.com`):** Heavily utilized by reputable SMS marketing platforms to conserve 160-character carrier quotas.
2. **Authentication Keywords (`/login`, `/verify`):** Every legitimate bank, e-commerce store, and SaaS platform uses `/login` and `/account`.
3. **Deep Subdomains:** Corporate clouds and enterprise CDNs legitimately deploy 3+ subdomain levels.
4. **Tracking Parameters:** Analytic suites append long redirect and campaign tokens to normal URLs.

Because of these realities, ScamShield treats structural indicators solely as contextual risk multipliers, never as definitive verdicts.

---

## 10. Security Boundary & Explicit Non-Goals

### Security Boundary:
**Strictly Offline.** The code contains zero imports of:
`requests`, `urllib.request`, `httpx`, `aiohttp`, `socket`, `http.client`, `selenium`, `playwright`, or `urllib3`.
This is verified by an automated AST audit in [`tests/test_url_analysis.py`](file:///c:/Users/radika/OneDrive/Desktop/ScamShieldAI/tests/test_url_analysis.py#L210).

### Explicit Non-Goals for Phase 4:
- No DNS resolution or domain reachability checks.
- No WHOIS registration age lookups.
- No HTTP requests, redirect chain traversal, or webpage content inspection.
- No external threat intelligence feeds (VirusTotal, Google Safe Browsing).
- No homoglyph brand impersonation dictionaries (reserved for semantic analysis).
- No modifications or retraining of the Phase 3 ML text classifier.
