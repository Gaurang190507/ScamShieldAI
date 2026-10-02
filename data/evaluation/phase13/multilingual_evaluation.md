# ScamShield AI — Phase 13 Multilingual Generalization Report

**Evaluation Date**: October 2, 2026  
**Focus**: Generalization across Native Devanagari Hindi (`hi`) and Romanized Hinglish (`hi-Latn`).

---

## 1. Native Devanagari Hindi (`hi`) Evaluation (6 Scams, 6 Legitimate)

| Model | Accuracy | Precision | Recall (TP / 6) | F1 Score | FPR (FP / 6) |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **Model A (Baseline)** | 50.00% (6/12) | N/A (0/0) | **0.0% (0/6)** | 0.0000 | 0.0% (0/6) |
| **Model B (Char n-gram)** | 100.00% (12/12) | 100.0% (6/6) | **100.0% (6/6)** | 1.0000 | 0.0% (0/6) |
| **Model C (Semantic Dense)** | 75.00% (9/12) | 66.7% (6/9) | **100.0% (6/6)** | 0.8000 | 50.0% (3/6) |
| **Model D (Hybrid Fusion)** | 75.00% (9/12) | 100.0% (3/3) | **50.0% (3/6)** | 0.6667 | 0.0% (0/6) |

---

## 2. Romanized Hinglish (`hi-Latn`) Evaluation (6 Scams, 6 Legitimate)

| Model | Accuracy | Precision | Recall (TP / 6) | F1 Score | FPR (FP / 6) |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **Model A (Baseline)** | 66.67% (8/12) | 100.0% (2/2) | **33.3% (2/6)** | 0.5000 | 0.0% (0/6) |
| **Model B (Char n-gram)** | 100.00% (12/12) | 100.0% (6/6) | **100.0% (6/6)** | 1.0000 | 0.0% (0/6) |
| **Model C (Semantic Dense)** | 100.00% (12/12) | 100.0% (6/6) | **100.0% (6/6)** | 1.0000 | 0.0% (0/6) |
| **Model D (Hybrid Fusion)** | 83.33% (10/12) | 100.0% (4/4) | **66.7% (4/6)** | 0.8000 | 0.0% (0/6) |

---

## 3. Analysis & Linguistic Insights
- **Character-Level n-gram / Subword-Like Character Representations**: Model B's `char_wb` analyzer extracts 3-5 character n-grams directly within word boundaries from Unicode NFKC normalized text. This completely bypasses the English regex word-token boundary failure of Model A without requiring raw byte-level modeling.
- **Phonetic Invariance**: Romanized Hinglish exhibits wide spelling divergence ("khata", "khaata", "a/c"). Character n-grams capture overlapping phonetic subword roots, yielding 100.0% recall (6/6).
- **Dense Semantic Representation Limitation**: Model C (`all-MiniLM-L6-v2`) is an English-centric sentence transformer. While effective on Romanized Hinglish (100% recall), its Devanagari representations produce elevated false alarms (50.0% FPR, 3/6) due to out-of-distribution embedding distortions.
