# ScamShield AI — Phase 5 Hybrid Text+URL Evaluation Report 🔬

**Experiment:** Controlled Comparison of Phase 3 (Text-Only) vs Phase 5 (Hybrid Text+URL) Baseline  
**Dataset:** UCI SMS Spam Collection (`data/processed/preprocessed/uci_sms_spam.jsonl`)  
**Partitioning:** Reused exact Phase 3 leak-free split (3,881 Train / 837 Val / 856 Test)  

---

## 1. Full Test Set Comparison (856 Samples)

| Metric | Phase 3 (Text Only) | Phase 5 (Hybrid Text+URL) | Difference (Hybrid - Text) |
| :--- | :---: | :---: | :---: |
| **Accuracy** | 98.25% | 98.13% | -0.12% |
| **Scam Precision** | 95.76% | 95.73% | -0.03% |
| **Scam Recall** | 91.87% | 91.06% | -0.81% |
| **Scam F1-Score** | 93.78% | 93.33% | -0.45% |
| **ROC-AUC** | 0.9979 | 0.9957 | -0.0022 |
| **False Positives (FP)** | 5 | 5 | +0 |
| **False Negatives (FN)** | 10 | 11 | +1 |
| **True Positives (TP)** | 113 | 112 | -1 |

---

## 2. URL-Containing Test Subset Analysis

- **Total Test Messages:** 856
- **Messages Containing URLs:** 24 (2.80% of test partition)
- **Messages Without URLs:** 832 (97.20% of test partition)
- **Subset Class Balance:** 22 scam, 2 non-scam

### URL Subset Performance Comparison
| Metric | Phase 3 (Text Only) | Phase 5 (Hybrid) |
| :--- | :---: | :---: |
| **Accuracy** | 91.67% | 91.67% |
| **Scam Precision** | 91.67% | 91.67% |
| **Scam Recall** | 100.00% | 100.00% |
| **Scam F1-Score** | 95.65% | 95.65% |
| **Confusion Matrix** | TN: 0, FP: 2, FN: 0, TP: 22 | TN: 0, FP: 2, FN: 0, TP: 22 |

> **Statistical Limitation:** The URL-containing test subset contains only 24 messages (22 scam, 2 non-scam). This sample size is statistically limited and reflects 2011 historical SMS data. It must not be treated as a definitive evaluation of modern URL threat efficacy.

---

## 3. Ablation Experiment (Controlled 3-Way Comparison)

| Model Variant | Feature Description | Accuracy | Scam Prec | Scam Rec | Scam F1 | ROC-AUC |
| :--- | :--- | :---: | :---: | :---: | :---: | :---: |
| **Model A (Phase 3 Text Only Baseline)** | TF-IDF (1, 2) n-grams (10,637 features) | 98.25% | 95.76% | 91.87% | 93.78% | 0.9979 |
| **Model B (Text + Aggregate URL Presence & Risk)** | TF-IDF + has_url, url_count, max_risk_score, mean_risk_score (10,641 features) | 98.13% | 95.73% | 91.06% | 93.33% | 0.9956 |
| **Model C (Phase 5 Full Text + URL Structural Hybrid)** | TF-IDF + 25 message-level URL structural features (10,662 features) | 98.13% | 95.73% | 91.06% | 93.33% | 0.9957 |

---

## 4. Learned URL Feature Coefficients

| URL Feature | Coefficient | Interpretation |
| :--- | :---: | :--- |
| `has_url` | `+1.6793` | Model assigned positive association with scam class. |
| `url_count` | `+1.6793` | Model assigned positive association with scam class. |
| `max_hostname_length` | `+0.7526` | Model assigned positive association with scam class. |
| `max_subdomain_depth` | `+0.7510` | Model assigned positive association with scam class. |
| `max_url_length` | `+0.7315` | Model assigned positive association with scam class. |
| `max_url_risk_score` | `+0.2254` | Model assigned positive association with scam class. |
| `mean_url_risk_score` | `+0.2254` | Model assigned positive association with scam class. |
| `has_insecure_http` | `+0.2254` | Model assigned positive association with scam class. |
| `max_query_parameter_count` | `+0.0269` | Model assigned positive association with scam class. |
| `has_unusual_scheme` | `+0.0000` | Neutral / Zero occurrences in training split. |

---

## 5. Model Differential & Error Analysis

Total Prediction Differentials at Threshold 0.30: **1** / 856 samples.

### Key Differential Case:
- **[uci_sms_0228]** (True: `scam`): Text: *"Will u meet ur dream partner soon? Is ur career off 2 a flyng start? 2 find out free, txt ..."*
  - Phase 3 Text Model: Prob = `0.359` -> `scam`
  - Phase 5 Hybrid Model: Prob = `0.286` -> `non_scam`
  - Root Cause: Message contains no URL. Introduction of strong positive `has_url` weight slightly lowered non-URL boundary scores.

---

## 6. Key Scientific Takeaways & Dataset Limitations

1. **Dominant Text Baseline:** On the historical UCI SMS collection, text alone achieves 98.25% accuracy and 93.78% scam F1. Scam messages with URLs already contain overwhelming text spam keywords, leaving negligible headroom for URL features to improve recall.
2. **Sparse URL Distribution:** Only 1.94% of UCI messages contain URLs (24 in test split). Because modern evasive URL attacks (e.g., innocent text lures concealing malicious shortened links) are absent from 2011 carrier SMS, URL structural features do not significantly shift discrimination.
3. **Experimental Conclusion:** The hybrid experiment validates the technical pipeline and proves zero data leakage, but emphasizes that modern phishing/scam datasets are required to evaluate real-world URL threat utility.
