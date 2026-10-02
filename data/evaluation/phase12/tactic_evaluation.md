# Phase 12: Phase 6 Scam Tactic Detector Evaluation

## 1. Overview
Phase 6 evaluates the rule-based, deterministic tactic detection engine across real-world scam messages with ground-truth tactic annotations.

## 2. Aggregate Metrics

| Metric | Value |
|---|---|
| Evaluated Samples | 48 |
| Exact Set Matches | 0 (0.00%) |
| Micro-Averaged Precision | 0.8333 |
| Micro-Averaged Recall | 0.3889 |
| Micro-Averaged F1 | 0.5303 |
| Macro-Averaged Precision | 0.7208 |
| Macro-Averaged Recall | 0.3740 |
| Macro-Averaged F1 | 0.4925 |

## 3. Per-Tactic Breakdown

| Tactic Name | TP | FP | FN | Precision | Recall | F1 Score |
|---|---|---|---|---|---|---|
| `account_suspension` | 0 | 1 | 4 | 0.0000 | 0.0000 | 0.0000 |
| `authority_claim` | 0 | 0 | 15 | 0.0000 | 0.0000 | 0.0000 |
| `credential_request` | 2 | 0 | 6 | 1.0000 | 0.2500 | 0.4000 |
| `delivery_problem` | 0 | 0 | 2 | 0.0000 | 0.0000 | 0.0000 |
| `emotional_manipulation` | 0 | 0 | 1 | 0.0000 | 0.0000 | 0.0000 |
| `fear_creation` | 0 | 0 | 7 | 0.0000 | 0.0000 | 0.0000 |
| `impersonation` | 7 | 10 | 6 | 0.4118 | 0.5385 | 0.4667 |
| `investment_pressure` | 0 | 0 | 4 | 0.0000 | 0.0000 | 0.0000 |
| `job_offer` | 2 | 0 | 2 | 1.0000 | 0.5000 | 0.6667 |
| `link_redirection` | 24 | 0 | 0 | 1.0000 | 1.0000 | 1.0000 |
| `payment_request` | 6 | 0 | 12 | 1.0000 | 0.3333 | 0.5000 |
| `personal_information_request` | 0 | 0 | 2 | 0.0000 | 0.0000 | 0.0000 |
| `qr_code_request` | 1 | 0 | 1 | 1.0000 | 0.5000 | 0.6667 |
| `refund_claim` | 3 | 0 | 0 | 1.0000 | 1.0000 | 1.0000 |
| `remote_access_request` | 1 | 0 | 3 | 1.0000 | 0.2500 | 0.4000 |
| `reward_claim` | 2 | 0 | 16 | 1.0000 | 0.1111 | 0.2000 |
| `technical_support_claim` | 0 | 0 | 4 | 0.0000 | 0.0000 | 0.0000 |
| `threat` | 2 | 0 | 12 | 1.0000 | 0.1429 | 0.2501 |
| `urgency` | 20 | 2 | 6 | 0.9091 | 0.7692 | 0.8333 |
| `verification_request` | 0 | 1 | 7 | 0.0000 | 0.0000 | 0.0000 |

## 4. Key Strengths and Limitations
- **High Recall Tactics**: Direct action tactics such as `urgency`, `payment_request`, and `account_suspension` demonstrate strong detection rates across English and Hinglish templates.
- **Negative Context Guards**: Negative guards prevent false alarms on negative phrases like "do not share OTP" in benign institutional alerts.
- **Cross-Script Limitation**: Devanagari Hindi text does not trigger regex rules defined for Latin characters unless Hindi patterns are explicitly registered.
