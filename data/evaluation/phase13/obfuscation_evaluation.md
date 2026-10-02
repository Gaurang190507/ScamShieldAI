# ScamShield AI — Phase 13 Obfuscation Robustness Report

**Evaluation Date**: October 2, 2026  
**Focus**: Evasion resistance against syntactically perturbed messages and controlled pairs.

---

## 1. Controlled Pair Robustness Analysis

Evaluates 10 controlled pairs (Original Base Message vs. Syntactically Perturbed Variant, 20 total samples).  
Perturbations include:
- Character Spacing (`S B I`, `a c c o u n t`)
- Leetspeak Substitutions (`b10cked`, `p@ssw0rd`)
- Punctuation Injection (`E.l.e.c.t.r.i.c.i.t.y`, `H.D.F.C`)
- Emoji Padding & Character Repetitions

| Model | Total Controlled Pairs | Label Flips | Label Flip Rate (Flips / 10) |
| :--- | :--- | :--- | :--- |
| **Model A (Baseline)** | 10 | 0 | **0.0% (0/10)** |
| **Model B (Char n-gram)** | 10 | 0 | **0.0% (0/10)** |
| **Model D (Hybrid Fusion)** | 10 | 1 | **10.0% (1/10)** |

> **Clarification on Phase 12 vs. Phase 13 Obfuscation Measurements**:  
> Phase 12 previously reported a controlled obfuscation label-flip rate of 10.0%. Phase 13 reports a 0.0% Model A flip rate on its controlled obfuscation benchmark. Phase 12's 10.0% controlled-obfuscation flip rate and Phase 13's 0.0% Model A flip rate were measured on different controlled-obfuscation benchmark instances. The Phase 13 benchmark was newly constructed with 10 independent controlled pairs (20 samples) to ensure zero data leakage against the frozen Phase 12 test set, and is therefore not directly comparable to the Phase 12 measurement. The Phase 12 result remains frozen and unchanged.

---

## 2. Obfuscated Benchmark Performance (20 Scam Samples)

| Model | Accuracy | Precision | Recall (TP / 20) | F1 Score |
| :--- | :--- | :--- | :--- | :--- |
| **Model A (Baseline)** | 60.00% (12/20) | 100.0% (12/12) | **60.0% (12/20)** | 0.7500 |
| **Model B (Char n-gram)** | 100.00% (20/20) | 100.0% (20/20) | **100.0% (20/20)** | 1.0000 |
| **Model C (Semantic Dense)** | 90.00% (18/20) | 100.0% (18/18) | **90.0% (18/20)** | 0.9474 |
| **Model D (Hybrid Fusion)** | 95.00% (19/20) | 100.0% (19/19) | **95.0% (19/20)** | 0.9744 |

---

## 3. Robustness Mechanisms
- **Subword Overlap**: When an attacker injects spaces (`S B I`), word-level models see three single-letter tokens and discard them. In contrast, character-level n-gram models with `char_wb` and n=3-5 retain partial cross-token fragments that preserve the scam indicator.
- **Leetspeak Invariance**: Character n-grams over `b10cked` produce `['10c', '0ck', 'cke']` which maintain high partial similarity with `blocked`.
