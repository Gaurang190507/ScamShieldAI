# ScamShield AI — Phase 5: Hybrid Text + URL Baseline Experiment Documentation

## 1. Objective of the Experiment

The primary objective of **Phase 5** was to execute an offline, strictly controlled machine learning experiment to determine whether augmenting text features with passive, structural URL features from Phase 4 improves scam/non-scam classification performance over the reference Phase 3 text-only baseline.

This experiment adhered to strict scientific controls:
- The **Phase 3 text-only baseline** model, feature representations, hyperparameters, training partition, and validation-selected decision threshold remained completely frozen as the control group.
- The **Phase 4 URL analyzer** remained frozen as an upstream deterministic component without modifying heuristics, weights, or severity rules.
- **Zero data leakage**: Split partitions, TF-IDF vocabulary fitting, and URL feature scalers were strictly isolated to the training set.
- **100% offline**: Zero network calls, DNS queries, or external threat intelligence APIs were used.

---

## 2. Models Compared

| Attribute | Model A (Phase 3 Reference Control) | Model C (Phase 5 Hybrid Text + URL) |
| :--- | :--- | :--- |
| **Model Type** | Logistic Regression | Logistic Regression |
| **Text Feature Extraction** | Word & Bigram TF-IDF (1, 2) | Word & Bigram TF-IDF (1, 2) |
| **Text Vocabulary Size** | 10,637 n-grams | 10,637 n-grams (exact match) |
| **URL Features** | None | 25-dimensional message-level vector |
| **URL Feature Scaling** | N/A | `MaxAbsScaler` (fitted on train only) |
| **Total Features** | 10,637 | 10,662 (10,637 text + 25 URL) |
| **Regularization ($C$)** | 1.0 ($L_2$ penalty, `lbfgs`) | 1.0 ($L_2$ penalty, `lbfgs`) |
| **Random State** | 42 | 42 |
| **Selected Threshold** | 0.30 (validation F1 optimal) | 0.30 (validation F1 optimal) |

---

## 3. Feature Representation Details

### 3.1 Text Features
- **Algorithm**: `TfidfVectorizer` from `scikit-learn`
- **N-gram Range**: (1, 2) [unigrams and bigrams]
- **Min Document Frequency (`min_df`)**: 2
- **Max Document Frequency (`max_df`)**: 0.90
- **Sublinear Term Frequency (`sublinear_tf`)**: True ($1 + \log(\text{tf})$)
- **Accent Stripping**: Unicode normalization
- **Fitting Scope**: Fitted exclusively on the 3,881 training samples. Vocabulary size: **10,637**.

### 3.2 URL Feature Vector Composition (25 Dimensions)
For each message, URLs are identified via `entities["urls"]` or extracted using the Phase 2 regex extractor. For messages with no URLs, an exact all-zero vector is generated. For messages containing one or more URLs, features are deterministically aggregated:

1. **Presence & Frequency (2 features)**:
   - `has_url`: Binary indicator (1.0 if URL present, 0.0 otherwise).
   - `url_count`: Total number of URLs detected in message.
2. **Aggregated Risk Scores (2 features)**:
   - `max_url_risk_score`: Maximum overall heuristic risk score across all URLs in the message ($\in [0.0, 1.0]$).
   - `mean_url_risk_score`: Arithmetic mean heuristic risk score across all URLs in the message ($\in [0.0, 1.0]$).
3. **Phase 4 Heuristic Signal Triggers (14 features)**:
   - `has_unusual_scheme`: 1.0 if any URL uses non-http(s) schemes (e.g. data, file).
   - `has_userinfo_present`: 1.0 if any URL embeds authentication credentials in authority.
   - `has_ip_based_hostname`: 1.0 if hostname is raw IPv4 or IPv6.
   - `has_plain_http_sensitive`: 1.0 if plain HTTP is combined with sensitive keywords.
   - `has_unusual_port`: 1.0 if port is non-standard (not 80/443/8080/8443).
   - `has_excessive_subdomain_depth`: 1.0 if subdomain depth exceeds 3 levels.
   - `has_punycode_hostname`: 1.0 if hostname uses `xn--` encoding.
   - `has_suspicious_path_keywords`: 1.0 if path contains high-risk credential/banking tokens.
   - `has_suspicious_query_parameters`: 1.0 if query parameters contain tracking/session hijack tokens.
   - `has_known_shortener`: 1.0 if domain matches known URL shortener registry.
   - `has_non_ascii_hostname`: 1.0 if hostname contains non-ASCII characters.
   - `has_excessive_url_length`: 1.0 if URL length exceeds 100 characters.
   - `has_excessive_percent_encoding`: 1.0 if percent-encoding count exceeds 5.
   - `has_insecure_http`: 1.0 if URL uses unencrypted `http://`.
4. **Structural Dimension Aggregates (7 features)**:
   - `max_url_length`: Maximum total character length of any URL in message.
   - `max_hostname_length`: Maximum hostname character length.
   - `max_subdomain_depth`: Maximum number of subdomain labels.
   - `max_query_parameter_count`: Maximum number of query parameters.
   - `max_percent_encoded_count`: Maximum count of `%XX` sequences.
   - `ip_url_count`: Total number of URLs pointing directly to IP addresses.
   - `shortener_url_count`: Total number of URLs matching known shortener domains.

### 3.3 Scaling Method and Rationale
- **Scaler**: `MaxAbsScaler`
- **Rationale**: 
  1. **Preserves Exact Sparsity**: For 98.06% of the corpus containing no URLs, all 25 features are zero. Unlike `StandardScaler` (which subtracts the mean and destroys zero-value semantics, resulting in dense matrices), `MaxAbsScaler` leaves zero values identically 0.0.
  2. **Bounded Output**: Scales each dense feature by its maximum absolute training value, constraining dense features into $[0.0, 1.0]$.
  3. **Leakage Safety**: Fitted strictly on the training partition URL feature matrix.

---

## 4. Dataset Partitioning & Training Details

### 4.1 Partition Isolation
Partitioning strictly replicated the Phase 3 leakage-safe split generated via connected-component graph clustering of duplicate text hashes:
- **Total Corpus**: 5,574 samples (`data/processed/preprocessed/uci_sms_spam.jsonl`) — 4,827 non-scam, 747 scam
- **Training Set**: 3,881 samples (69.63%) — 3,361 non-scam, 520 scam (73 messages with URLs = 1.88%)
- **Validation Set**: 837 samples (15.02%) — 733 non-scam, 104 scam (11 messages with URLs = 1.31%)
- **Test Set**: 856 samples (15.36%) — 733 non-scam, 123 scam (24 messages with URLs = 2.80%)
- **Leakage Verification**: Zero sample ID overlap and zero raw text string overlap across train, validation, and test splits.

### 4.2 Threshold Selection
- Threshold was tuned exclusively on the **Validation Set** across thresholds $0.10 \dots 0.90$ with step size 0.05.
- Both Phase 3 and Phase 5 selected **0.30** as the optimal threshold based on maximizing scam F1-score:
  - Validation metrics at 0.30: Accuracy = 98.09%, Scam Precision = 95.83%, Scam Recall = 88.46%, Scam F1 = 92.00%.

---

## 5. Experimental Results

### 5.1 Full Test Set Comparison (856 Samples, Threshold = 0.30)

| Metric | Phase 3 (Text Only) | Phase 5 (Hybrid Text+URL) | Delta (Hybrid - Text) |
| :--- | :---: | :---: | :---: |
| **Accuracy** | 98.25% | 98.13% | **-0.12%** |
| **Scam Precision** | 95.76% | 95.73% | **-0.03%** |
| **Scam Recall** | 91.87% | 91.06% | **-0.81%** |
| **Scam F1-Score** | 93.78% | 93.33% | **-0.45%** |
| **ROC-AUC** | 0.9979 | 0.9957 | **-0.0022** |
| **True Negatives (TN)** | 728 | 728 | $\pm 0$ |
| **False Positives (FP)** | 5 | 5 | $\pm 0$ |
| **False Negatives (FN)** | 10 | 11 | **+1** |
| **True Positives (TP)** | 113 | 112 | **-1** |

### 5.2 URL-Containing Test Subset Analysis (24 Samples)
- **Total Test Messages with URLs**: 24 (2.80% of test split)
- **Class Balance**: 22 scam, 2 non-scam

| Metric | Phase 3 (Text Only) | Phase 5 (Hybrid Text+URL) | Delta |
| :--- | :---: | :---: | :---: |
| **Accuracy** | 91.67% | 91.67% | 0.00% |
| **Scam Precision** | 91.67% | 91.67% | 0.00% |
| **Scam Recall** | 100.00% | 100.00% | 0.00% |
| **Scam F1-Score** | 95.65% | 95.65% | 0.00% |
| **Confusion Matrix** | TN: 0, FP: 2, FN: 0, TP: 22 | TN: 0, FP: 2, FN: 0, TP: 22 | Identical |

> [!NOTE]
> On the 24 test messages containing URLs, both the text-only and hybrid models achieve **identical predictions and identical metrics**. The text model already attained 100% recall on these messages, leaving zero headroom for the URL features to improve recall on this subset.

### 5.3 Controlled 3-Way Ablation Study

| Model Identifier | Features Description | Total Dims | Test Accuracy | Scam Prec | Scam Recall | Scam F1 | ROC-AUC |
| :--- | :--- | :---: | :---: | :---: | :---: | :---: | :---: |
| **Model A** | Phase 3 Text Only Baseline | 10,637 | **98.25%** | **95.76%** | **91.87%** | **93.78%** | **0.9979** |
| **Model B** | Text + Agg URL Presence & Risk (`has_url`, `url_count`, `max_risk`, `mean_risk`) | 10,641 | 98.13% | 95.73% | 91.06% | 93.33% | 0.9956 |
| **Model C** | Full Phase 5 Hybrid (Text + 25 URL features) | 10,662 | 98.13% | 95.73% | 91.06% | 93.33% | 0.9957 |

---

## 6. Error Analysis & Differential Cases

Across all 856 test set samples, exactly **1 prediction differed** between the Phase 3 text model and Phase 5 hybrid model at the 0.30 decision threshold:

### 6.1 The Single Differential Case: `uci_sms_0228`
- **Sample ID**: `uci_sms_0228`
- **Ground Truth**: `scam`
- **Text**: *"Will u meet ur dream partner soon? Is ur career off 2 a flyng start? 2 find out free, txt horoscope then your star sign to 87088. eg horoscope stella"*
- **URL Count**: 0 (No URLs present)
- **Phase 3 Text Model**: Probability = `0.3590` $\rightarrow$ Predicted: `scam` (True Positive)
- **Phase 5 Hybrid Model**: Probability = `0.2860` $\rightarrow$ Predicted: `non_scam` (False Negative)
- **Root Cause Analysis**:
  Because `has_url` received a strong positive coefficient ($+1.6793$) during logistic regression optimization, the model learned that messages with URLs have an elevated prior probability of being spam. In compensating for this positive feature, the intercept and residual weighting slightly lowered predicted probabilities for borderline non-URL messages. Consequently, `uci_sms_0228` shifted from 0.3590 to 0.2860, falling just below the 0.30 threshold.

### 6.2 False Positives (FP) Analysis
Both models produced the **exact same 5 false positives** (3 without URLs, 2 with URLs):
1. **`uci_sms_1924`** (non-URL): Short informal chat misclassified due to ambiguous tokens.
2. **`uci_sms_3700`** (non-URL): Telecommunications carrier billing notice ("Free msg: ...").
3. **`uci_sms_4486`** (non-URL): Missed call alert service SMS.
4. **`uci_sms_0381`** (has URL): Carrier broadcast notification: *"PRIVATE! Your 2003 Account Statement shows 800 un-redeemed S.I.M. points. Call 08718738001 Identifier Code: 49557 Expires 26/11/04... visit http://www.bcast.info..."*
5. **`uci_sms_1447`** (has URL): WAP portal download prompt: *"LOOK AT THE STARS CHECK OUT THE WAP SITE http://wap. ... TO FIND OUT MORE"*
*Insight*: Both URL false positives are legitimate carrier promotions and WAP service pushes that use aggressive promotional language identical to contemporary scams.

### 6.3 False Negatives (FN) Analysis
- Phase 3 produced 10 false negatives; Phase 5 produced 11 (the 10 common FNs plus `uci_sms_0228`).
- **Zero false negatives** occurred among URL-containing messages in either model (100% recall on URL messages).
- All false negatives were short, evasive SMS messages lacking traditional spam keywords (e.g., subtle conversational hooks).

---

## 7. Learned URL Feature Coefficients

Inspection of the Logistic Regression model weights (`classifier.coef_[0]`) for the 25 URL features reveals what the model learned:

| URL Feature | Learned Coefficient | Direction / Association | Interpretation |
| :--- | :---: | :---: | :--- |
| `has_url` | `+1.6793` | Positive (Scam) | Baseline indicator that URLs strongly correlate with promotional/spam SMS in 2011. |
| `url_count` | `+1.6793` | Positive (Scam) | Scaled identically to presence for single-URL messages. |
| `max_hostname_length` | `+0.7526` | Positive (Scam) | Long hostnames in mobile SMS indicate external domains rather than short carrier codes. |
| `max_subdomain_depth` | `+0.7510` | Positive (Scam) | Deep subdomain hierarchies correlated with third-party hosting. |
| `max_url_length` | `+0.7315` | Positive (Scam) | Long URLs consumed scarce 160-char SMS limits, indicative of automated spam blasts. |
| `max_url_risk_score` | `+0.2254` | Positive (Scam) | Passive heuristic risk score positively associated with scam class. |
| `mean_url_risk_score` | `+0.2254` | Positive (Scam) | Mean heuristic risk score positively associated with scam class. |
| `has_insecure_http` | `+0.2254` | Positive (Scam) | Unencrypted HTTP links were common in 2011 spam campaigns. |
| `max_query_parameter_count` | `+0.0269` | Positive (Scam) | Tracking parameters in SMS links. |
| `has_unusual_scheme` | `0.0000` | Neutral / Zero | Zero occurrences in 2011 SMS training partition. |
| `has_userinfo_present` | `0.0000` | Neutral / Zero | Zero occurrences in 2011 SMS training partition. |
| `has_unusual_port` | `0.0000` | Neutral / Zero | Zero occurrences in 2011 SMS training partition. |
| `has_punycode_hostname` | `0.0000` | Neutral / Zero | Zero occurrences in 2011 SMS training partition. |
| `has_non_ascii_hostname` | `0.0000` | Neutral / Zero | Zero occurrences in 2011 SMS training partition. |
| `has_excessive_percent_encoding` | `0.0000` | Neutral / Zero | Zero occurrences in 2011 SMS training partition. |

> [!NOTE]
> **Why `has_url` and `url_count` have identical coefficients (+1.6793):**
> Across the entire training split of 3,881 messages, exactly 73 messages contain URLs and 3,808 do not. Every single URL-containing message contains **exactly one URL** (0 messages contain 2+ URLs). Consequently, the feature vectors for `has_url` and `url_count` are perfectly collinear (identical column vectors). Under $L_2$ regularization, identical inputs receive split, equal weights ($+1.6793$). For the exact same reason, `max_url_risk_score` and `mean_url_risk_score` are identical ($+0.2254$).

---

## 8. Discussion & Dataset Limitations

### 8.1 Why URL Features Did Not Improve Overall Classification
1. **Dominant Text Baseline**: The TF-IDF text representation on the UCI SMS dataset already achieves 98.25% accuracy and 93.78% scam F1. In 2011 carrier SMS, spam messages containing URLs also contained prominent text tokens ("claim", "free", "winner", "urgent", "prize"). The text model already detected **100% of scam messages with URLs** ($22/22$).
2. **Extreme URL Sparsity**: Only 108 of 5,574 messages (1.94%) contain URLs. In the 856-sample test split, only 24 messages contain URLs. An input feature that is identically zero for 97.20% of test samples cannot materially alter full-dataset aggregate accuracy.
3. **Absence of Modern Evasion Tactics**: In modern phishing (e.g. WhatsApp, iMessage, SMS), attackers deliberately write benign-sounding lure text (e.g. *"Hi Dad, my phone is broken, please approve this payment: https://bit.ly/..."*) to bypass keyword filters. The 2011 UCI dataset contains zero instances of this evasion tactic.

### 8.2 Statistical Limitations
The URL-containing test subset consists of only 24 samples (22 scam, 2 non-scam). While providing an exact, reproducible sanity check for pipeline mechanics, this sample size is too small to draw statistically generalizable conclusions about URL risk efficacy in modern production environments.

### 8.3 Implications for Future Phases
- The offline hybrid pipeline infrastructure (feature extraction, scaling, matrix stacking, inference) is verified and leak-free.
- Future phases evaluating URL threat signals must benchmark against modern phishing datasets (e.g. modern SMS/WhatsApp lures, smishing benchmarks) where text and URL features provide orthogonal, complementary signals.

---

## 9. Reproducibility & Artifact Inventory

### 9.1 Commands
- **Retrain Hybrid Model and Regenerate Evaluation**:
  ```bash
  python -m src.models.hybrid_baseline
  ```
- **Execute Phase 5 Unit Tests**:
  ```bash
  python -m unittest tests/test_hybrid_model.py
  ```
- **Execute Full Test Suite**:
  ```bash
  python -m unittest discover tests
  ```

### 9.2 Model Checkpoints (`models/hybrid/`)
| File | Size (Bytes) | Description |
| :--- | :---: | :--- |
| `tfidf_vectorizer.joblib` | 234,234 | Scikit-learn TF-IDF vectorizer (10,637 n-grams fitted on train). |
| `url_scaler.joblib` | 847 | `MaxAbsScaler` fitted on 25 training URL features. |
| `logistic_regression.joblib` | 86,159 | Trained Scikit-learn Logistic Regression estimator ($C=1.0$). |
| `model_metadata.json` | 773 | Model parameters, thresholds, and environment metadata. |

### 9.3 Evaluation Artifacts (`data/evaluation/hybrid/`)
| File | Size (Bytes) | Description |
| :--- | :---: | :--- |
| `metrics.json` | 5,853 | Comprehensive threshold tuning and test split evaluation metrics. |
| `confusion_matrix.json` | 625 | Confusion matrices at 0.30 and 0.50 thresholds vs Phase 3. |
| `comparison.json` | 1,430 | Side-by-side metric comparison and delta computations. |
| `url_subset_metrics.json` | 1,625 | Isolated evaluation on the 24 test messages containing URLs. |
| `ablation_results.json` | 2,504 | 3-way ablation comparison (Model A vs Model B vs Model C). |
| `feature_coefficients.json` | 2,611 | Learned weights and magnitudes for all 25 URL features. |
| `test_predictions.jsonl` | 265,395 | Full line-by-line test predictions (856 samples). |
| `error_analysis.jsonl` | 4,738 | Detailed failure cases and false positive/negative records. |
| `README.md` | 4,936 | Human-readable experimental summary report. |
