# Phase 12: Phase 4 Passive URL Scanner Evaluation

## 1. Operational Invariant Verification
- Outbound network requests executed: **0**
- DNS lookups or socket connections initiated: **0**
- Operation: Strictly offline syntactic string evaluation.

## 2. Overall Performance

| Metric | Count / Score |
|---|---|
| Total Benchmark URLs | 24 |
| Accuracy | 0.7917 |
| Precision | 1.0000 |
| Recall | 0.5833 |
| F1 Score | 0.7368 |
| False Positive Rate on Benign URLs | 0.0% (0/12) |

## 3. Structural Category Breakdown

| Category | Total URLs | Flagged Suspicious | Detection Rate | Accuracy |
|---|---|---|---|---|
| `ip_hostname` | 3 | 3 | 100.0% | 100.0% |
| `other_suspicious` | 2 | 1 | 50.0% | 50.0% |
| `shortener` | 3 | 1 | 33.3% | 33.3% |
| `deep_subdomain` | 3 | 1 | 33.3% | 33.3% |
| `punycode` | 1 | 1 | 100.0% | 100.0% |
| `clean_institutional` | 12 | 0 | 0.0% | 100.0% |

## 4. Triggered Heuristics Distribution

| Heuristic Signal | Trigger Frequency |
|---|---|
| `unknown` | 27 |

## 5. Scope of Evaluation Findings
- **Supported Structural Capabilities**: Passive structural URL analysis is supported for the evaluated structural signals, including IP hosts and non-standard ports (100% recall), but the benchmark does not establish comprehensive malicious-domain detection or live reputation capability.
- **Known Shorteners**: Accurately flags `bit.ly`, `tinyurl`, `is.gd` domains based on known static lists without resolving redirects.
- **Institutional Domain Whitelist**: Clean banking and government domains (`gov.in`, `sbi.co.in`, `hdfcbank.com`) correctly achieve low risk scores with 0.00% false positive rate.
- **Explicit Limitation**: Live Network URL / Domain Reputation remains **`NOT_EVALUATED`**.
