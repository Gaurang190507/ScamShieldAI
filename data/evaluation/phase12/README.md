# Phase 12: Real-World Robustness & Generalization Evaluation

**Status:** `PHASE 12 — COMPLETE / FROZEN`

## Overview
Phase 12 conducts an empirical evaluation of the frozen ScamShield AI detection pipeline (Phases 1–11) against modern, realistic threats beyond the historical UCI SMS benchmark and synthetic visual fixtures.

### Architectural Invariant
All upstream phases remain **strictly frozen and unmodified**:
- Phase 3: Text Classifier (TF-IDF + Logistic Regression)
- Phase 4: Passive URL Analyzer (structural heuristics)
- Phase 5: Text + URL Hybrid Experiment
- Phase 6: Scam Tactic & Evidence Engine
- Phase 7: Semantic Similarity & Novelty Detector
- Phase 8: Multi-Signal Risk Aggregator
- Phase 9A: OCR Extractor
- Phase 9B: Visual Classifier
- Phase 10: RAG + Explanation Engine
- Phase 11: Investigation Service

### Evaluation Rating Definitions
- **`SUPPORTED`**: A capability demonstrated acceptable behavior for the specific evaluated scope and benchmark, without implying universal or production-level coverage.
- **`LIMITED`**: The capability functions but measured performance, coverage, or robustness is insufficient for broad claims.
- **`NOT_EVALUATED`**: No meaningful empirical evaluation was performed for that capability.

*(These labels describe evaluation scope, not an overall quality ranking.)*

### Interpretation of `mixed_signals`
`mixed_signals` indicates that the deterministic signals were contradictory or insufficiently aligned for a strong directional assessment. It should not be interpreted as a correct scam classification merely because the ground-truth label is scam. Outcomes where `ground_truth = scam` and `system = mixed_signals` remain non-definitive outcomes, not true positives.

### Benchmark Datasets
All evaluation data is strictly quarantined in `data/evaluation/phase12/`:
1. `modern_scam_patterns/modern_indian_scams.jsonl`: 20 modern Indian scam vectors (digital arrest, electricity cutoff, UPI scratch card, e-challan APK, bank KYC suspension, task scam, etc.).
2. `hard_negatives/hard_negatives.jsonl`: 20 authentic institutional alerts containing urgency or verification language (bank OTPs, BESCOM utility bills, Amazon delivery PINs, ITR filing alerts, etc.).
3. `multilingual/multilingual_cases.jsonl`: 14 native Devanagari Hindi (5) and romanized Hinglish (9) cases.
4. `obfuscated/obfuscated_cases.jsonl`: 10 controlled perturbation pairs (leetspeak, spacing, emoji injection, punctuation delimiters, typos).
5. `novel_patterns/novel_scam_patterns.jsonl`: 10 novel scam patterns (Web3 staking yield, AI voice clone emergency, cold wallet seed phrase airdrop, GPU node validator).
6. `urls/url_benchmark.jsonl`: 24 passive URLs (IP hosts, non-standard ports, deep subdomains, shorteners, punycode, clean institutional portals).
7. `screenshots/screenshot_cases.jsonl`: 10 screenshot evaluation cases.

### Evaluation Reports
1. [Dataset Report](dataset_report.md)
2. [Classification Evaluation](classification_evaluation.md)
3. [Tactic Evaluation](tactic_evaluation.md)
4. [URL Evaluation](url_evaluation.md)
5. [Semantic Evaluation](semantic_evaluation.md)
6. [Aggregation Evaluation](aggregation_evaluation.md)
7. [Multilingual Evaluation](multilingual_evaluation.md)
8. [Robustness Evaluation](robustness_evaluation.md)
9. [Error Analysis](error_analysis.md)
10. [Security Audit](security_audit.md)
11. [Performance Evaluation](performance_evaluation.md)
12. [Phase 12 Final Report](phase12_final_report.md)
