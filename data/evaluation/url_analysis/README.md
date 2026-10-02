# ScamShield AI — Phase 4 URL Analysis Evaluation Report 🔗

**Component:** Passive Offline URL Analysis & Threat Heuristics  
**Source Dataset:** UCI SMS Spam Collection (`data/processed/preprocessed/uci_sms_spam.jsonl`)  
**Operational Mode:** 100% Offline (Zero outbound HTTP/DNS requests, deterministic string analysis)  

---

## 1. Corpus URL Extraction Overview

- **Total SMS Messages Analyzed:** 5574
- **Messages Containing URLs:** 108 (1.94%)
- **Total URL Mentions:** 108
- **Unique URLs:** 67
- **Malformed / Unparseable URLs:** 8

---

## 2. Structural Feature Statistics

### Schemes Distribution
| Scheme | Mention Count |
| :--- | :---: |
| `no_scheme` | 86 |
| `http` | 14 |

### Host & Authority Structural Signals
- **IP-based Hostnames:** 0
- **Punycode Hostnames:** 0
- **Non-ASCII Hostnames:** 0
- **Known Link Shorteners:** 0
- **Excessive Subdomain Depth (>=3):** 0
- **Unusual Ports:** 0
- **Userinfo Present:** 0

### URL Length Statistics
- Mean: `19.45` characters
- Median: `18.0` characters
- Range: `[11, 41]` characters

---

## 3. Heuristic Signal Frequency

| Heuristic Signal | Mentions Triggered | Prevalence (%) |
| :--- | :---: | :---: |
| `insecure_http` | 14 | 12.96% |
| `malformed_url` | 8 | 7.41% |

---

## 4. Heuristic Risk Distribution

| Risk Band | Qualitative Level | Count | Proportion |
| :--- | :--- | :---: | :---: |
| `[0.00, 0.24]` | Low | 100 | 92.59% |
| `[0.25, 0.49]` | Moderate | 0 | 0% |
| `[0.50, 0.74]` | High | 0 | 0% |
| `[0.75, 1.00]` | Very High | 0 | 0% |

### Score Metrics
- **Mean Heuristic Score:** `0.0065`
- **Median Heuristic Score:** `0.0`
- **Score Range:** `[0.0, 0.05]`

---

## 5. Security & Isolation Boundary

- **Zero Outbound Calls:** Verified 100% offline string analysis.
- **No Label Leakage:** Scam/non-scam labels were never used to tune or calibrate heuristic weights.
- **No ML Modification:** Phase 3 baseline models remain frozen and independent.
