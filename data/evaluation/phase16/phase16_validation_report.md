# ScamShield AI — Phase 16 Real-World Validation Report

## 1. Executive Summary
- **Validation Dataset**: Independent Phase 16 Real-World Corpus (`data/evaluation/phase16/phase16_dataset_manifest.jsonl`)
- **Total Samples Evaluated**: 90 (61 Scam, 29 Non-Scam)
- **Overall Binary Accuracy**: 46.67% (42/90)
- **Scam Precision**: 84.21% (16/19)
- **Scam Recall**: 26.23% (16/61)
- **Scam F1 Score**: 0.4000
- **Hard-Negative False Positive Rate (FPR)**: 6.67% (1/15)
- **False Negative Rate (FNR)**: 73.77% (45/61)

## 2. Confusion Matrix (Strict Policy)
| | Predicted Likely Scam | Predicted Not Likely Scam (Mixed / Non-Scam) | Total Ground Truth |
|---|---|---|---|
| **Actual Scam** | **16 (TP)** | 45 (FN) | 61 |
| **Actual Non-Scam** | 3 (FP) | **26 (TN)** | 29 |
| **Total Predicted** | 19 | 71 | 90 |

## 3. Deterministic Risk Status Distribution
Under Phase 8 risk aggregation, cases are assigned to one of four discrete statuses:

| Risk Status | Total Cases | Ground Truth Scam | Ground Truth Non-Scam | Scam Purity | Non-Scam Purity |
|---|---|---|---|---|---|
| **`likely_scam`** | 19 (21.1%) | 16 | 3 | 84.2% | 15.8% |
| **`mixed_signals`** | 45 (50.0%) | 35 | 10 | 77.8% | 22.2% |
| **`likely_non_scam`** | 26 (28.9%) | 10 | 16 | 38.5% | 61.5% |

> [!NOTE]
> **Interpretation of `mixed_signals`:**
> A total of 45 samples (50.0% of corpus) were categorized as `mixed_signals`.
> Of these, 35 are scams and 10 are non-scams.
> In an operational security triage pipeline, `mixed_signals` serves as an active warning flag requiring secondary investigation.
> When both `likely_scam` (16) and `mixed_signals` (35) are treated as *intercepted threats*, **51 out of 61 scams (83.61%) are caught**, with only 10 scams (16.39%) slipping into `likely_non_scam`.

## 4. Subgroup Performance Analysis

### 4.1 Linguistic Breakdown
| Language / Script | Total Samples | Scam Samples | True Positives | False Positives | Strict Recall | Precision | F1 Score |
|---|---|---|---|---|---|---|---|
| `English (Latin)` | 78 | 54 | 15 | 3 | 27.8% (15/54) | 83.3% | 0.4167 |
| `Hindi (Devanagari)` | 4 | 2 | 0 | 0 | 0.0% (0/2) | 0.0% | 0.0000 |
| `Hinglish (Romanized)` | 5 | 3 | 1 | 0 | 33.3% (1/3) | 100.0% | 0.5000 |
| `Mixed Script` | 3 | 2 | 0 | 0 | 0.0% (0/2) | 0.0% | 0.0000 |

### 4.2 Evaluation Category Breakdown (C1–C8)
| Case Group | Total Cases | Scam Cases | Detected as Likely Scam | Strict Recall | Overall Accuracy | Primary Characterization |
|---|---|---|---|---|---|---|
| `C1_common_scams` | 20 | 20 | 9 | 45.0% (9/20) | 45.0% | Common real-world retail scams (KYC, UPI, parcel, jobs) |
| `C2_unknown_emerging` | 10 | 10 | 1 | 10.0% (1/10) | 10.0% | Emerging / novel scam storylines (digital arrest, AI clone, ESG) |
| `C3_hard_negatives` | 15 | 0 | 0 | N/A (All Benign) | 93.3% | Legitimate institutional notices resembling scams (OTPs, statements) |
| `C4_multilingual` | 12 | 7 | 1 | 14.3% (1/7) | 50.0% | Devanagari, Romanized Hindi, and mixed-script variations |
| `C5_obfuscated` | 10 | 8 | 3 | 37.5% (3/8) | 50.0% | Character spacing, punctuation, leetspeak, and emojis |
| `C6_url_cases` | 10 | 6 | 1 | 16.7% (1/6) | 30.0% | Isolated URLs, IP hosts, shortened links, institutional domains |
| `C7_screenshot_cases` | 8 | 5 | 1 | 20.0% (1/5) | 50.0% | Rendered screenshot images evaluated via OCR and visual modules |
| `C8_adversarial_injection` | 5 | 5 | 0 | 0.0% (0/5) | 0.0% | Adversarial prompt injection and system override attempts |

## 5. Multi-Label Tactic Detection Performance
- **Tactic Micro Precision**: 0.1398
- **Tactic Micro Recall**: 0.0807
- **Tactic Micro F1**: 0.1024
- **Exact Set Match Rate**: 17.78% (16/90)

| Tactic Label | True Positives (TP) | False Positives (FP) | False Negatives (FN) | Precision | Recall | F1 |
|---|---|---|---|---|---|---|
| `account_suspension` | 0 | 2 | 0 | 0.0000 | 0.0000 | 0.0000 |
| `action_demand` | 0 | 0 | 28 | 0.0000 | 0.0000 | 0.0000 |
| `adversarial_override` | 0 | 0 | 5 | 0.0000 | 0.0000 | 0.0000 |
| `authority_impersonation` | 0 | 0 | 39 | 0.0000 | 0.0000 | 0.0000 |
| `credential_request` | 0 | 1 | 0 | 0.0000 | 0.0000 | 0.0000 |
| `emotional_manipulation` | 0 | 0 | 2 | 0.0000 | 0.0000 | 0.0000 |
| `fear_creation` | 0 | 1 | 0 | 0.0000 | 0.0000 | 0.0000 |
| `impersonation` | 0 | 29 | 0 | 0.0000 | 0.0000 | 0.0000 |
| `isolation_tactic` | 0 | 0 | 1 | 0.0000 | 0.0000 | 0.0000 |
| `job_offer` | 0 | 2 | 0 | 0.0000 | 0.0000 | 0.0000 |
| `legal_threat` | 0 | 0 | 6 | 0.0000 | 0.0000 | 0.0000 |
| `link_redirection` | 0 | 32 | 0 | 0.0000 | 0.0000 | 0.0000 |
| `novelty_lure` | 0 | 0 | 1 | 0.0000 | 0.0000 | 0.0000 |
| `payment_demand` | 0 | 0 | 20 | 0.0000 | 0.0000 | 0.0000 |
| `payment_request` | 0 | 6 | 0 | 0.0000 | 0.0000 | 0.0000 |
| `refund_claim` | 0 | 2 | 0 | 0.0000 | 0.0000 | 0.0000 |
| `remote_access_request` | 0 | 1 | 0 | 0.0000 | 0.0000 | 0.0000 |
| `reward_promise` | 0 | 0 | 18 | 0.0000 | 0.0000 | 0.0000 |
| `threat` | 0 | 1 | 0 | 0.0000 | 0.0000 | 0.0000 |
| `trust_building` | 0 | 0 | 7 | 0.0000 | 0.0000 | 0.0000 |
| `urgency` | 13 | 1 | 21 | 0.9286 | 0.3824 | 0.5417 |
| `verification_request` | 0 | 2 | 0 | 0.0000 | 0.0000 | 0.0000 |
