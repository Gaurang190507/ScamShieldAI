# ScamShield AI — Phase 13 Final Evaluation & Generalization Report

**Report Date**: October 2, 2026  
**Author**: ScamShield AI Core Engineering Team  
**Final Status**: **PHASE 13 — COMPLETE / FROZEN**

---

## 1. Objective

Phase 13 systematically evaluated and implemented experimental architectures to address the real-world generalization gaps identified in the frozen Phase 12 evaluation:
1. Native Devanagari Hindi smishing detection (Phase 12 baseline: 0.0% recall).
2. Romanized Hinglish smishing detection (Phase 12 baseline: 33.3% recall).
3. Modern Indian threat vectors (Digital Arrest, Electricity Cutoff, KYC Phishing).
4. Syntactic evasion via character spacing, leetspeak, and punctuation injection.
5. Preservation of high-urgency legitimate communications discrimination (Hard Negatives).

---

## 2. Frozen Baseline References

- **Phase 3 Baseline**: TF-IDF (Word-level) + Logistic Regression, threshold = `0.30`.
- **Phase 12 Benchmark**: Consolidated Real-World Benchmark (Accuracy: 50.00%, Recall: 27.08%).
- **Phase 12 Status**: Immutably preserved and frozen.

---

## 3. Dataset Architecture & Leakage Verification

All datasets generated under `data/evaluation/phase13/`:
- **Training Set (`train.jsonl`)**: 55 samples
- **Validation Set (`val.jsonl`)**: 20 samples (Used strictly for threshold calibration)
- **Test Set (`test.jsonl`)**: 31 samples (Held-out evaluation)
- **Hard Negatives (`hard_negatives.jsonl`)**: 25 samples
- **Multilingual (`multilingual_cases.jsonl`)**: 24 samples
- **Obfuscation (`obfuscated_cases.jsonl`)**: 20 samples (10 controlled pairs)
- **Novel Patterns (`novel_patterns.jsonl`)**: 16 samples

### Leakage Audit Results:
- Train vs. UCI SMS Exact Overlap: **0** (PASS)
- Train vs. UCI SMS Normalized Overlap: **0** (PASS)
- Train vs. Phase 7 Semantic Reference Overlap: **0** (PASS)
- Train vs. Phase 12 Benchmark Overlap: **0** (PASS)
- Cross-split Train vs. Val / Test Overlap: **0** (PASS)
- Augmentation Group Isolation Violations: **0** (PASS)

---

## 4. Controlled Subgroup Performance Matrix with Exact Denominators

| Subgroup | Model A (Frozen Baseline) | Model B (Char n-gram TF-IDF) | Model C (Offline Semantic) | Model D (Hybrid Fusion) |
| :--- | :---: | :---: | :---: | :---: |
| **Historical English Recall** | 100.0% (3/3) | 66.7% (2/3) | 66.7% (2/3) | 66.7% (2/3) |
| **Modern Indian English Recall** | 40.0% (2/5) | **80.0% (4/5)** | 100.0% (5/5) | 100.0% (5/5) |
| **Romanized Hinglish Recall** | 33.3% (2/6) | **100.0% (6/6)** | 100.0% (6/6) | 66.7% (4/6) |
| **Native Devanagari Hindi Recall**| 0.0% (0/6) | **100.0% (6/6)** | 100.0% (6/6) | 50.0% (3/6) |
| **Obfuscated Messages Recall** | 60.0% (12/20) | **100.0% (20/20)** | 90.0% (18/20) | 95.0% (19/20) |
| **Obfuscated Controlled-Pair Flip Rate** | 0.0% (0/10) | **0.0% (0/10)** | N/A | 10.0% (1/10) |
| **Hard-Negative False Positive Rate** | **4.0% (1/25)** | **4.0% (1/25)** | 52.0% (13/25) | 32.0% (8/25) |
| **Novel Threat Patterns Recall** | 25.0% (4/16) | **31.2% (5/16)** | 81.2% (13/16) | 75.0% (12/16) |
| **Consolidated Test Accuracy** | 48.39% (15/31) | **83.87% (26/31)** | 87.10% (27/31) | 83.87% (26/31) |
| **Consolidated Test F1 Score** | 0.4666 | **0.8780** | 0.9048 | 0.8780 |

---

## 5. Architectural Findings & Selection Rationale

1. **Model Selection**:
   - **Model B (`CharNgramClassifier`) is selected as the primary experimental candidate under the hard-negative constraint** rather than overall best model.
   - Model B was selected because it provided substantial multilingual and obfuscation improvements while maintaining the lowest observed hard-negative false-positive rate (**4.0%, 1/25**) among the improved models.
   - Model C demonstrated stronger consolidated (F1: 0.9048) and novel-pattern recall (81.3%, 13/16) but produced an unacceptable hard-negative false-positive rate (**52.0%, 13/25**) on this benchmark and was therefore not selected as the primary standalone classifier.
2. **Phase 12 vs. Phase 13 Obfuscation Clarification**:
   - Phase 12 previously reported a controlled obfuscation label-flip rate of 10.0%. Phase 13 reports a 0.0% Model A flip rate on its controlled obfuscation benchmark. Phase 12's 10.0% controlled-obfuscation flip rate and Phase 13's 0.0% Model A flip rate were measured on different controlled-obfuscation benchmark instances. The Phase 13 benchmark was newly constructed with 10 independent controlled pairs (20 samples) to ensure zero data leakage against the frozen Phase 12 test set, and is therefore not directly comparable to the Phase 12 measurement. The Phase 12 result remains frozen and unchanged.
3. **Tactic-Aware Learning Finding**:
   - Adding explicit tactic/URL features directly to the statistical classifier (Model D) did not improve Model B's consolidated F1 (**0.8780**) and sharply increased hard-negative FPR from **4.0% (1/25)** to **32.0% (8/25)**.
   - Deterministic tactic and URL analysis remain more appropriately represented in the forensic evidence layer rather than being unrestricted statistical classifier features. This conclusion is scoped to this Phase 13 benchmark.
4. **Novelty & Scope Limitations**:
   - Phase 13 improves linguistic generalization but does not establish reliable detection of previously unseen scam concepts. Novel-threat detection remains an open research and evaluation problem (**Model B novel-threat recall = 31.25%, 5/16**).
   - Low semantic similarity alone is **not** evidence of scam status. Known benign transactional messages also exhibit high novelty relative to reference spam corpora.
   - The Phase 13 training set contains 55 samples. Phase 13 demonstrates experimental improvement on the evaluated controlled benchmarks. The relatively small training and subgroup evaluation datasets limit the strength of broad generalization claims. The results should therefore be interpreted as evidence of measured improvement rather than production-level guarantees.

---

## 6. Security Invariants
- 100% offline execution confirmed (zero outbound requests, zero DNS queries, zero external API dependencies).

---

## 7. Final Phase Decision

> **PHASE 13 — COMPLETE / FROZEN**

Clarifications:
- Phase 1–12 remain frozen and unchanged.
- Phase 13 is an additive experimental layer.
- Phase 3 remains the historical frozen baseline/control.
- Phase 13 Model B is the primary experimental candidate under the hard-negative constraint.
- Phase 13 does not replace the deterministic forensic evidence architecture.
- Unknown/new scam detection remains an open research problem.
- No Phase 14 work is started.
