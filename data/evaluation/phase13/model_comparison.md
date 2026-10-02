# ScamShield AI — Phase 13 Model Comparison Report

**Evaluation Date**: October 2, 2026  
**Status**: COMPLETE / EMPIRICAL AUDIT  
**Scope**: Controlled multi-model comparison across 7 distinct threat and linguistic subgroups.

---

## 1. Experimental Models Evaluated

1. **Model A (Frozen Phase 3 Baseline Control)**:
   - Word-level TF-IDF (`ngram_range=(1,2)`) + Logistic Regression
   - Operating Threshold: `0.30` (Frozen historical threshold)
2. **Model B (Character-Level / Subword-Like Character TF-IDF)**:
   - Character n-grams within word boundaries (`char_wb`, `ngram_range=(3,5)`) + Logistic Regression
   - Operating Threshold: `0.55` (Calibrated on Phase 13 validation set)
3. **Model C (Offline Dense Semantic Representation)**:
   - Dense embeddings via `sentence-transformers/all-MiniLM-L6-v2` (384-d) + Logistic Regression
   - Operating Threshold: `0.50` (Calibrated on Phase 13 validation set)
4. **Model D (Multimodal Hybrid Fusion)**:
   - Character n-gram text features + Phase 6 Tactic vector (25-d) + Phase 4 URL heuristics (15-d) + Logistic Regression
   - Operating Threshold: `0.50` (Calibrated on Phase 13 validation set)

---

## 2. Subgroup Performance Matrix with Exact Denominators

### Historical English

| Model | Accuracy | Precision | Recall (TP / Pos) | F1 Score | FPR (FP / Neg) |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **Model_A_Baseline** | 100.00% (5/5) | 100.0% (3/3) | 100.0% (3/3) | 1.0000 | 0.0% (0/2) |
| **Model_B_CharNgram** | 80.00% (4/5) | 100.0% (2/2) | 66.7% (2/3) | 0.8000 | 0.0% (0/2) |
| **Model_C_SemanticDense** | 80.00% (4/5) | 100.0% (2/2) | 66.7% (2/3) | 0.8000 | 0.0% (0/2) |
| **Model_D_HybridFusion** | 80.00% (4/5) | 100.0% (2/2) | 66.7% (2/3) | 0.8000 | 0.0% (0/2) |

### Modern Indian English

| Model | Accuracy | Precision | Recall (TP / Pos) | F1 Score | FPR (FP / Neg) |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **Model_A_Baseline** | 40.00% (2/5) | 100.0% (2/2) | 40.0% (2/5) | 0.5714 | 0.0% (0/0) |
| **Model_B_CharNgram** | 80.00% (4/5) | 100.0% (4/4) | 80.0% (4/5) | 0.8889 | 0.0% (0/0) |
| **Model_C_SemanticDense** | 100.00% (5/5) | 100.0% (5/5) | 100.0% (5/5) | 1.0000 | 0.0% (0/0) |
| **Model_D_HybridFusion** | 100.00% (5/5) | 100.0% (5/5) | 100.0% (5/5) | 1.0000 | 0.0% (0/0) |

### Romanized Hinglish

| Model | Accuracy | Precision | Recall (TP / Pos) | F1 Score | FPR (FP / Neg) |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **Model_A_Baseline** | 66.67% (8/12) | 100.0% (2/2) | 33.3% (2/6) | 0.5000 | 0.0% (0/6) |
| **Model_B_CharNgram** | 100.00% (12/12) | 100.0% (6/6) | 100.0% (6/6) | 1.0000 | 0.0% (0/6) |
| **Model_C_SemanticDense** | 100.00% (12/12) | 100.0% (6/6) | 100.0% (6/6) | 1.0000 | 0.0% (0/6) |
| **Model_D_HybridFusion** | 83.33% (10/12) | 100.0% (4/4) | 66.7% (4/6) | 0.8000 | 0.0% (0/6) |

### Native Devanagari Hindi

| Model | Accuracy | Precision | Recall (TP / Pos) | F1 Score | FPR (FP / Neg) |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **Model_A_Baseline** | 50.00% (6/12) | N/A (0/0) | 0.0% (0/6) | 0.0000 | 0.0% (0/6) |
| **Model_B_CharNgram** | 100.00% (12/12) | 100.0% (6/6) | 100.0% (6/6) | 1.0000 | 0.0% (0/6) |
| **Model_C_SemanticDense** | 75.00% (9/12) | 66.7% (6/9) | 100.0% (6/6) | 0.8000 | 50.0% (3/6) |
| **Model_D_HybridFusion** | 75.00% (9/12) | 100.0% (3/3) | 50.0% (3/6) | 0.6667 | 0.0% (0/6) |

### Obfuscated Messages

| Model | Accuracy | Precision | Recall (TP / Pos) | F1 Score | FPR (FP / Neg) |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **Model_A_Baseline** | 60.00% (12/20) | 100.0% (12/12) | 60.0% (12/20) | 0.7500 | 0.0% (0/0) |
| **Model_B_CharNgram** | 100.00% (20/20) | 100.0% (20/20) | 100.0% (20/20) | 1.0000 | 0.0% (0/0) |
| **Model_C_SemanticDense** | 90.00% (18/20) | 100.0% (18/18) | 90.0% (18/20) | 0.9474 | 0.0% (0/0) |
| **Model_D_HybridFusion** | 95.00% (19/20) | 100.0% (19/19) | 95.0% (19/20) | 0.9744 | 0.0% (0/0) |

### Hard Negatives

| Model | Accuracy | Precision | Recall (TP / Pos) | F1 Score | FPR (FP / Neg) |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **Model_A_Baseline** | 96.00% (24/25) | 0.0% (0/1) | 0.0% (0/0) | 0.0000 | 4.0% (1/25) |
| **Model_B_CharNgram** | 96.00% (24/25) | 0.0% (0/1) | 0.0% (0/0) | 0.0000 | 4.0% (1/25) |
| **Model_C_SemanticDense** | 48.00% (12/25) | 0.0% (0/13) | 0.0% (0/0) | 0.0000 | 52.0% (13/25) |
| **Model_D_HybridFusion** | 68.00% (17/25) | 0.0% (0/8) | 0.0% (0/0) | 0.0000 | 32.0% (8/25) |

### Novel Threat Patterns

| Model | Accuracy | Precision | Recall (TP / Pos) | F1 Score | FPR (FP / Neg) |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **Model_A_Baseline** | 25.00% (4/16) | 100.0% (4/4) | 25.0% (4/16) | 0.4000 | 0.0% (0/0) |
| **Model_B_CharNgram** | 31.25% (5/16) | 100.0% (5/5) | 31.2% (5/16) | 0.4762 | 0.0% (0/0) |
| **Model_C_SemanticDense** | 81.25% (13/16) | 100.0% (13/13) | 81.2% (13/16) | 0.8966 | 0.0% (0/0) |
| **Model_D_HybridFusion** | 75.00% (12/16) | 100.0% (12/12) | 75.0% (12/16) | 0.8571 | 0.0% (0/0) |

### Consolidated Test Set

| Model | Accuracy | Precision | Recall (TP / Pos) | F1 Score | FPR (FP / Neg) |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **Model_A_Baseline** | 48.39% (15/31) | 100.0% (7/7) | 30.4% (7/23) | 0.4666 | 0.0% (0/8) |
| **Model_B_CharNgram** | 83.87% (26/31) | 100.0% (18/18) | 78.3% (18/23) | 0.8780 | 0.0% (0/8) |
| **Model_C_SemanticDense** | 87.10% (27/31) | 100.0% (19/19) | 82.6% (19/23) | 0.9048 | 0.0% (0/8) |
| **Model_D_HybridFusion** | 83.87% (26/31) | 100.0% (18/18) | 78.3% (18/23) | 0.8780 | 0.0% (0/8) |

---

## 3. Findings & Model Selection Logic

1. **Native Devanagari Hindi**:
   - Model A recorded **0.0% recall (0/6)** on native Hindi, failing entirely due to word tokenization out-of-vocabulary limitations.
   - Model B achieved **100.0% recall (6/6)** and **1.0000 F1**, demonstrating that character-level n-grams (`char_wb`, n=3-5) successfully resolve non-Latin script tokenization.
2. **Romanized Hinglish**:
   - Model A achieved only **33.3% recall (2/6)** (F1: 0.5000).
   - Both Model B and Model C achieved **100.0% recall (6/6)** (F1: 1.0000).
3. **Hard Negative Discrimination Tradeoff**:
   - Model B matched Model A with a low False Positive Rate of **4.0% (1/25)** on hard negatives (24/25 correctly identified as legitimate).
   - In contrast, Model C suffered an unacceptable **52.0% FPR (13/25)** and Model D suffered a **32.0% FPR (8/25)**, showing that dense semantic embeddings and unrestricted tactic indicators conflate legitimate high-urgency notifications with fraud.
4. **Model Selection Rationale**:
   - Model B was selected as the **primary experimental candidate under the hard-negative constraint** rather than overall best model.
   - Model B provided substantial multilingual and obfuscation improvements while maintaining the lowest observed hard-negative false-positive rate among the improved models. Model C demonstrated stronger consolidated and novel-pattern performance but produced an unacceptable hard-negative false-positive rate on this benchmark and was therefore not selected as the primary standalone classifier.
