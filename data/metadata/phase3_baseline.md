# Phase 3 Baseline Text Classification Specification & Report 🛡️

**Model Identity:** ScamShield Phase 3 baseline text classifier trained and evaluated on the UCI SMS Spam Collection.  
**Scope:** Text-only binary baseline (`scam` vs `non_scam`).  

---

## 1. Objective

The objective of Phase 3 is to establish an empirical, reproducible, and leakage-safe **machine learning baseline** for ScamShield AI.

This baseline answers a critical architectural question:
> *How well can a simple, classical, text-only model (TF-IDF + Logistic Regression) perform on basic spam/scam discrimination before any advanced features (URL heuristics, tactical multi-label indicators, semantic embeddings, novelty detection, or multimodal inspection) are added?*

Establishing this baseline provides a benchmark against which all future, more sophisticated ScamShield components will be measured.

---

## 2. Dataset & Scope

- **Primary Source:** UCI SMS Spam Collection (5,574 messages).
- **File Used:** `data/processed/preprocessed/uci_sms_spam.jsonl` (verified in Phase 2).
- **Label Mapping:**
  - `ham` ➔ `non_scam`: 4,827 samples (86.60%)
  - `spam` ➔ `scam`: 747 samples (13.40%)
  - Total: 5,574 samples
- **Important Constraint:**
  This model is strictly evaluated on historical carrier SMS text. It is **NOT** described as "the complete ScamShield system" or "production-ready scam detection." It is a foundational baseline.

---

## 3. Model Inputs & Target

- **Input:** Canonical `text` field exclusively.
  - To prevent feature leakage and establish a true text-only baseline, no preprocessing counts (`url_count`, `phone_count`), derived features (`otp_related`, `amount_values`), or metadata fields (`scam_category`, `tactics`, `urgency_level`) were provided to the model.
- **Target:** Canonical `label` (`scam` mapped to `1`, `non_scam` mapped to `0`).

---

## 4. Leakage-Safe Splitting Architecture & Outcome B Disclosure

### Grouping Reality (Outcome B Disclosure):
In the raw UCI SMS Spam Collection, `pattern_group_id` values were assigned during initial ingestion as unique per-row values (`grp_uci_unassigned_<row>`). All 5,574 records exist as singleton groups (0 multi-record groups). Consequently, `pattern_group_id` in UCI does **not** provide natural campaign-level template groupings. Describing this purely as "campaign group isolation" would be inaccurate.

### Repaired Splitting Strategy:
To prevent severe data leakage from repeated messages, ScamShield AI clusters samples using **normalized text deduplication clusters** (`_split_cluster_id`):
- All exact and normalized-identical messages (5,159 unique text clusters) are bound together into the same split partition.
- If genuine multi-record pattern groups exist, they are preserved within the same partition.
- **Result:** Zero duplicate text leakage across Train, Validation, and Test sets (verified 0 exact overlap and 0 normalized text overlap).
- **Random Seed:** `42` (deterministic).
- **Target Proportions:** ~70% Train, ~15% Validation, ~15% Test.

### Partition Breakdown

| Partition | Total Samples | Proportion | Scam Samples | Non-Scam Samples | Scam Ratio |
| :--- | :---: | :---: | :---: | :---: | :---: |
| **Train** | 3,881 | 69.63% | 520 | 3,361 | 13.40% |
| **Validation** | 837 | 15.02% | 104 | 733 | 12.43% |
| **Test** | 856 | 15.36% | 123 | 733 | 14.37% |
| **Total** | **5,574** | **100.00%** | **747** | **4,827** | **13.40%** |

*Leakage Verification:* Zero duplicate text leakage (0 exact and 0 normalized text overlaps across all partitions).

---

## 5. TF-IDF Vectorizer Configuration

The TF-IDF vectorizer was **fitted exclusively on training data** (`X_train_text`). The validation and test sets were transformed using the frozen training vocabulary.

- **N-gram Range:** `(1, 2)` (captures individual words and two-word collocations like *"call now"*, *"urgent claim"*).
- **Minimum Document Frequency (`min_df`):** `2` (prunes singleton typos and nonce tokens appearing only once).
- **Maximum Document Frequency (`max_df`):** `0.90` (prunes corpus-wide stop words appearing in >90% of documents).
- **Sublinear Term Frequency (`sublinear_tf`):** `True` (replaces raw term count \(tf\) with \(1 + \log(tf)\), dampening the influence of repeated words).
- **Accent Stripping:** `unicode` (normalizes diacritics).
- **Vocabulary Size:** `10,637` distinct word and bigram features.

---

## 6. Logistic Regression Configuration

- **Estimator:** `sklearn.linear_model.LogisticRegression`
- **Regularization Strength (\(C\)):** `1.0` (standard L2 regularization).
- **Solver:** `lbfgs` (Limited-memory Broyden–Fletcher–Goldfarb–Shanno, robust for sparse text matrices).
- **Maximum Iterations (`max_iter`):** `1000` (ensures complete convex convergence).
- **Random State:** `42` (reproducible).

---

## 7. Validation Threshold Analysis

In imbalanced binary classification (86.6% negative vs 13.4% positive), a standard default threshold of `0.50` often produces high precision at the expense of recall.

To address this, candidate thresholds were systematically evaluated on the **Validation Set only**:

| Candidate Threshold | Val Accuracy | Val Scam Precision | Val Scam Recall | Val Scam F1-Score |
| :---: | :---: | :---: | :---: | :---: |
| **0.30** | **98.09%** | **95.83%** | **88.46%** | **0.9200** (Best F1) |
| 0.40 | 97.49% | 100.00% | 78.85% | 0.8817 |
| 0.50 (Default) | 96.06% | 100.00% | 67.31% | 0.8046 |
| 0.60 | 94.74% | 100.00% | 54.81% | 0.7081 |
| 0.70 | 92.59% | 100.00% | 40.38% | 0.5753 |

**Operating Threshold Decision:**
Threshold `0.30` was selected based on validation set F1 maximization, recovering +21.15% more true positive scam messages on validation data while maintaining 95.83% precision on validation data.

---

## 8. Final Test Set Evaluation Results

The final test set (856 samples) was evaluated using both the tuned threshold (`0.30`) and the default reference (`0.50`):

### Operating Threshold: 0.30 (Validation-Tuned)
- **Accuracy**: `98.25%`
- **ROC-AUC**: `0.9979`
- **Scam Precision**: `95.76%`
- **Scam Recall**: `91.87%`
- **Scam F1-Score**: `93.78%`
- **Macro Average F1**: `96.38%`
- **Weighted Average F1**: `98.23%`

**Confusion Matrix (0.30):**
```text
                  Predicted Non-Scam    Predicted Scam
Actual Non-Scam          728                  5         (FP)
Actual Scam               10                113         (TP)
                         (FN)
```

### Reference Threshold: 0.50 (Default)
- **Accuracy**: `96.38%`
- **ROC-AUC**: `0.9979`
- **Scam Precision**: `100.00%`
- **Scam Recall**: `74.80%` (31 false negatives)
- **Scam F1-Score**: `85.58%`

**Confusion Matrix (0.50):**
```text
                  Predicted Non-Scam    Predicted Scam
Actual Non-Scam          733                  0         (FP)
Actual Scam               31                 92         (TP)
```

---

## 9. Error Analysis & Hard Negatives

Detailed error cases are recorded in `data/evaluation/baseline/error_analysis.jsonl`. Total errors at threshold 0.30: 15 cases (5 FP, 10 FN).

### False Positives (5 cases at threshold 0.30)
Non-scam messages containing commercial vocabulary or call cues that crossed the threshold:
1. `uci_sms_2380` & `uci_sms_4774` (prob: `0.3764`): *"Hi, Mobile no. <#> has added you in their contact list on www.fullonsms.com It s a great place to send free sms to people..."*  
   *Root Cause:* The tokens `"mobile"`, `"contact"`, `"free sms"`, `"people"` trigger marketing spam weights.
2. `uci_sms_3365` (prob: `0.3852`): *"Can... I'm free..."*  
   *Root Cause:* Short ambiguous message triggering positive association with `"free"`.
3. `uci_sms_4305` (prob: `0.3308`): *"Yup i'm free..."*  
   *Root Cause:* Triggered by `"free"`.
4. `uci_sms_4703` (prob: `0.3271`): *"I liked the new mobile"*  
   *Root Cause:* Triggered by token `"mobile"`.

### False Negatives (10 cases at threshold 0.30)
True scam/spam messages that evaded text classification:
1. **Conversational Adult Chat/Dating:** E.g., `uci_sms_1270` (*"Can U get 2 phone NOW? I wanna chat 2 set up meet Call me NOW..."*, prob: `0.1714`), `uci_sms_5373` (*"dating:i have had two of these..."*, prob: `0.1815`). They lack traditional commercial keywords like *"prize"*, *"win"*, or *"claim"*.
2. **Subscription / Confirmation Prompts:** E.g., `uci_sms_1675` (*"Monthly password for wap. mobsi.com is 391784. Use your wap phone not PC."*, prob: `0.2623`), `uci_sms_2916` (*"Sorry! U can not unsubscribe yet..."*, prob: `0.2028`).
3. **News / Novelty Lures:** E.g., `uci_sms_5452` (*"Latest News! Police station toilet stolen, cops have nothing..."*, prob: `0.1460`), `uci_sms_3575` (*"You won't believe it but it's true. It's Incredible Txts!..."*, prob: `0.2813`).

---

## 10. System Limitations

This baseline has fundamental limitations that must be addressed in subsequent phases:
1. **Historical Corpus**: Ingested from the 2011 UCI SMS Spam Collection. It does not reflect modern fraud mechanisms (such as digital arrest, fake electricity bill disconnection, Aadhaar/PAN APK sideloading, or UPI request-money scams).
2. **Spam vs. Scam Distinction**: A large portion of UCI "spam" consists of commercial competitions and ringtone offers rather than criminal credential harvesting or financial extortion.
3. **Channel Restriction**: SMS-only (160 characters); does not model longer email transcripts, WhatsApp formatting, or multi-turn conversational scams.
4. **No Tactic or Behavioral Decomposition**: The model outputs a single scalar probability. It does not provide multi-label tactical indicators (urgency, impersonation, authority claims).
5. **No URL Threat Intelligence**: URLs are treated only as literal string tokens; no domain heuristics, registration age, or redirection graphs are analyzed.
6. **No Semantic or Out-of-Distribution Handling**: Lexical n-grams fail when adversarial paraphrasing or novel phrasing is introduced.

---

## 11. Artifacts Generated

- **Model Checkpoints:**
  - `models/baseline/tfidf_vectorizer.joblib`
  - `models/baseline/logistic_regression.joblib`
  - `models/baseline/model_metadata.json`
- **Evaluation Outputs:**
  - `data/evaluation/baseline/metrics.json`
  - `data/evaluation/baseline/confusion_matrix.json`
  - `data/evaluation/baseline/test_predictions.jsonl`
  - `data/evaluation/baseline/error_analysis.jsonl`
  - `data/evaluation/baseline/split_statistics.json`
  - `data/evaluation/baseline/README.md`
- **Reusable Inference Module:**
  - `src/models/baseline_classifier.py` (`predict(text)` interface)
- **Reproducible Training Pipeline:**
  - `src/models/train_baseline.py` (`python -m src.models`)

---

## 12. Next Phase Recommendations

- **Phase 4**: URL Analysis & Threat Intelligence heuristics (passive structural parsing, IP address detection, punycode, TLD risk analysis).
- **Phase 5**: Multi-label behavioral tactic classifiers (identifying urgency, impersonation, payment demands independently).
- **Phase 6**: Semantic similarity & out-of-distribution novelty detection for emerging scam patterns.
