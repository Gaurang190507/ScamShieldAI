# Phase 3 Dataset Splitting & Leakage Audit Report 🛡️

**Project:** ScamShield AI  
**Scope:** Dataset Splitting, Duplicate Handling, and Data Leakage Audit for Phase 3 ML Baseline  
**Date of Audit:** October 2, 2026  
**Auditor:** Antigravity AI  

---

## 1. Executive Summary

This audit rigorously inspected the dataset splitting methodology, duplicate handling, and leakage claims for the Phase 3 TF-IDF + Logistic Regression baseline on the UCI SMS Spam Collection (5,574 samples).

**Final Audit Status:** **PASS WITH REPAIR**

### Summary of Findings:
1. **Outcome B Confirmed:** The UCI SMS dataset possesses **no natural campaign/pattern group structure**. All 5,574 records had unique singleton IDs (`grp_uci_unassigned_<row>`). Describing the original split as "campaign-level template isolation" was misleading.
2. **Duplicate Leakage Detected in Initial Split:** Because records were split as individual rows, identical duplicate messages crossed partition boundaries (69 train/val, 73 train/test, 17 val/test; total 159 cross-partition leaks).
3. **Successful Repair Applied:** The splitting procedure in `src/models/train_baseline.py` was repaired to group records by **normalized text deduplication clusters** (`_split_cluster_id`). Duplicate messages are now strictly isolated within individual partitions with **0 exact** and **0 normalized** cross-split duplicates.
4. **Model Retrained on Leak-Free Split:** The baseline model was retrained on the leak-free training partition, validation threshold selection was re-verified (best threshold remains `0.30`), and final test evaluation was recomputed.
5. **Full Test Suite Passing:** All 89 existing unit tests plus 7 new split integrity tests (total 96 tests) pass cleanly.

---

## 2. Pattern Groups Distribution

Audit of `pattern_group_id` across the complete 5,574-record UCI dataset:

- **Total Records:** `5,574`
- **Total Unique Groups:** `5,574`
- **Singleton Groups (Size = 1):** `5,574` (`100.00%`)
- **Groups of Size 2:** `0` (`0.00%`)
- **Groups of Size 3+:** `0` (`0.00%`)
- **Largest Group Size:** `1`
- **Percentage of Records in Multi-Record Groups:** `0.00%`

### Conclusion on UCI Grouping:
Outcome B applies. The current UCI SMS Spam Collection contains no multi-record campaign templates or pattern clusters. The initial ingestion assigned synthetic row-level IDs. The splitter mechanically prevented group overlap, but because each group was a singleton, it was functionally an unstratified record-level split that permitted duplicate text leakage.

---

## 3. Duplicate Analysis

Audit of verbatim and normalized text repetitions across the 5,574 records:

- **Total Unique Exact Texts:** `5,160`
- **Total Records with Duplicate Exact Text:** `703` (414 excess instances)
- **Total Unique Normalized Texts:** `5,160`
- **Total Records with Duplicate Normalized Text:** `703` (414 excess instances)

### Cross-Split Duplicate Overlap:

| Overlap Boundary | Initial Split (Row Grouping) | Repaired Split (Text Cluster Grouping) |
| :--- | :---: | :---: |
| **Train / Validation** | 69 identical messages | **0** |
| **Train / Test** | 73 identical messages | **0** |
| **Validation / Test** | 17 identical messages | **0** |
| **Total Leaking Duplicate Pairs** | **159** | **0** |

---

## 4. Split Integrity

Audit of partition boundaries in the repaired dataset split:

- **Grouping Method:** Disjoint-set clustering grouping all samples sharing normalized text (and any multi-sample pattern groups) into unique `_split_cluster_id` clusters (5,159 unique clusters).
- **Partition Ratios:** ~70% Train, ~15% Validation, ~15% Test (Random State: `42`).

### Partition Breakdown:
- **Train Split:** `3,881` samples (`69.63%`) — 520 scam (`13.40%`), 3,361 non-scam (`86.60%`)
- **Validation Split:** `837` samples (`15.02%`) — 104 scam (`12.43%`), 733 non-scam (`87.57%`)
- **Test Split:** `856` samples (`15.36%`) — 123 scam (`14.37%`), 733 non-scam (`85.63%`)
- **Total Records Accounted For:** `5,574` / `5,574` (`100.0%`)

### Boundary Verification:
- **Do groups cross splits?** **NO** (0 cluster overlap, verified via `verify_no_group_leakage`).
- **Do exact texts cross splits?** **NO** (0 exact text overlap).
- **Do normalized texts cross splits?** **NO** (0 normalized text overlap).

---

## 5. TF-IDF Integrity

Audit of feature extraction and vocabulary fitting:

- **Fit Location:** `train_baseline.py` strictly executes `vectorizer.fit_transform(X_train_text)` on `train_df["text"]` only.
- **Transform Locations:** `vectorizer.transform(X_val_text)` on validation partition; `vectorizer.transform(X_test_text)` on test partition.
- **Vocabulary Size:** `10,637` features (frozen at training time).
- **Out-of-Vocabulary / Leakage Test:** Analysis of `test_df` identified 730 words appearing exclusively in the test set. **0** of these 730 test-exclusive words appear in the fitted TF-IDF vocabulary, proving zero test vocabulary leakage.

---

## 6. Threshold Integrity

Audit of operating threshold selection:

- **Candidate Thresholds:** `[0.30, 0.40, 0.50, 0.60, 0.70]`.
- **Selection Dataset:** Evaluated strictly on the **Validation Split only**.
  - Threshold `0.30`: Val F1 = `0.9200` (Acc = 98.09%, Prec = 95.83%, Rec = 88.46%)
  - Threshold `0.40`: Val F1 = `0.8817`
  - Threshold `0.50`: Val F1 = `0.8046`
  - Threshold `0.60`: Val F1 = `0.7081`
  - Threshold `0.70`: Val F1 = `0.5753`
- **Selection Rule:** Highest scam F1-score on the validation partition selected threshold `0.30`.
- **Final Evaluation Dataset:** Evaluated once on the **Test Split** using the frozen threshold (`0.30`) and the default reference (`0.50`). Test labels were not used during threshold tuning.

---

## 7. Test Set Isolation

- **Isolation Status:** **CONFIRMED**
- The test set was never accessed during preprocessing fit, TF-IDF vocabulary construction, Logistic Regression parameter estimation, or threshold tuning.
- Test evaluation was conducted as a single-pass inference step.

---

## 8. Repaired Baseline Performance Summary

Performance on the verified leak-free test partition (856 samples):

| Metric | Selected Operating Threshold (`0.30`) | Default Reference Threshold (`0.50`) |
| :--- | :---: | :---: |
| **Accuracy** | **98.25%** | 96.38% |
| **ROC-AUC** | **0.9979** | 0.9979 |
| **Scam Precision** | **95.76%** | 100.00% |
| **Scam Recall** | **91.87%** | 74.80% |
| **Scam F1-Score** | **93.78%** | 85.58% |
| **Macro Avg F1** | **96.38%** | 91.76% |
| **Weighted Avg F1** | **98.23%** | 96.15% |
| **True Negatives (TN)** | `728` | `733` |
| **False Positives (FP)** | `5` | `0` |
| **False Negatives (FN)** | `10` | `31` |
| **True Positives (TP)** | `113` | `92` |

---

## 9. Repairs Made

1. **Splitting Logic (`src/models/train_baseline.py`):**
   - Replaced row-level unassigned grouping with connected-component clustering (`_split_cluster_id`) grouping samples that share identical normalized text.
   - Added runtime validation ensuring 0 exact and 0 normalized text overlaps across Train, Val, and Test splits.
2. **Artifact Regeneration (`models/baseline/`, `data/evaluation/baseline/`):**
   - Retrained TF-IDF vectorizer and Logistic Regression model on the leak-free training partition.
   - Regenerated `model_metadata.json`, `metrics.json`, `confusion_matrix.json`, `test_predictions.jsonl`, `error_analysis.jsonl`, `split_statistics.json`, and `README.md`.
3. **Test Suite Updates (`tests/test_baseline_model.py`):**
   - Updated split count assertions to reflect the repaired partitions (3,881 train, 837 val, 856 test).
4. **Integrity Test Suite Created (`tests/test_phase3_split_integrity.py`):**
   - Added 7 rigorous automated regression tests covering ID non-overlap, exact text isolation, normalized duplicate isolation, multi-record pattern grouping, TF-IDF fit isolation, validation threshold selection, and test set single-pass evaluation.
5. **Documentation Updated (`data/metadata/phase3_baseline.md`):**
   - Documented Outcome B honestly (UCI pattern groups are singletons).
   - Documented text deduplication clustering and updated performance metrics.

---

## 10. Test Execution Verification

Command run:
```bash
python -m unittest discover tests
```

Results:
- **Previous Tests:** `89`
- **New Split Integrity Tests:** `7`
- **Total Tests:** `96`
- **Passed:** `96`
- **Failed:** `0`
- **Execution Time:** ~1.59s

---

## 11. Final Status

**PASS WITH REPAIR**

The Phase 3 ML baseline methodology is verified to be sound, reproducible, and completely free of cross-split duplicate text and label leakage.
