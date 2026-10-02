# ScamShield AI — Phase 13 Architecture and System Audit

**Audit Date**: October 2, 2026  
**Auditor**: ScamShield AI Core Engineering  
**Scope**: Pre-implementation audit of Phases 1–12 systems, contracts, schemas, artifacts, and generalization gaps to guide Phase 13 Generalization & Detection Improvement.

---

## 1. Executive Summary

Phase 12 established an empirical baseline for ScamShield AI across realistic, modern threat vectors. The frozen system demonstrated high performance on historical English benchmarks (98.25% test accuracy on UCI SMS), but exhibited significant generalization gaps when exposed to modern Indian scam patterns (40.0% recall), Romanized Hinglish (33.3% recall), and native Devanagari Hindi (0.0% recall with 100% vocabulary out-of-vocabulary rate).

The objective of **Phase 13** is to systematically research, implement, and evaluate experimental model architectures and multimodal feature representations that bridge these generalization gaps while preserving:
1. Frozen state of existing Phase 1–12 models, artifacts, datasets, and decision rules.
2. 100% offline security posture (zero socket/DNS/network activity).
3. Hard negative discrimination (ensuring urgency, OTPs, or banking notifications are not conflated with scams).
4. Full forensic explainability and auditability.
5. Strict group-level data leakage prevention.

---

## 2. Inventory of Frozen Components (Phases 1–12)

| Phase | Component / Module | Canonical Artifacts / Paths | Interfaces & Input/Output Schema | Operational Invariants |
| :--- | :--- | :--- | :--- | :--- |
| **Phase 1** | Ingestion & Data Governance | `data/raw/`, `data/processed/uci_sms_spam.jsonl` | Standardized JSONL schema: `text`, `label` (`ham`/`spam`), `split`, `sample_id` | Immutable source splits. |
| **Phase 2** | Deterministic Preprocessing | `src/preprocessing/` (`cleaner.py`, `normalize.py`, `extract_entities.py`) | Input: raw text string. Output: normalized text, extracted URLs, phone numbers, crypto addresses, UPI handles, currency amounts | Preserves character offsets for forensic grounding; no destructive stripping. |
| **Phase 3** | Baseline Text Classifier | `src/models/baseline_classifier.py`, `models/baseline/tfidf_vectorizer.joblib`, `models/baseline/logistic_regression.joblib` | Input: string. Output: `dict` with `label` (`scam`/`non_scam`), `probability`, `threshold` (0.30), `scam_probability`, `non_scam_probability` | Word-level TF-IDF (`ngram_range=(1,2)`, English regex token pattern `(?u)\b\w\w+\b`). Frozen threshold: `0.30`. |
| **Phase 4** | Passive URL Scanner | `src/url_analysis/` (`url_scanner.py`, `url_heuristics.py`, `url_features.py`) | Input: extracted URL list or raw text. Output: `URLRiskAssessment` (`risk_level`: low/med/high, `risk_score`, `signals_triggered`, 14 heuristic flags) | 100% passive, zero DNS or HTTP requests. Evaluates host structure, IP presence, path tokens, Punycode, shorteners. |
| **Phase 5** | Hybrid Feature Experiment | `src/models/hybrid_baseline.py`, `models/hybrid/` | Input: text + 25 URL features. Output: probability, classification label | Frozen ablation artifact. |
| **Phase 6** | Tactic & Evidence Engine | `src/tactics/` (`tactic_detector.py`, `tactic_rules.py`, `schemas.py`) | Input: text string. Output: `TacticResult` with `detected_tactics: List[DetectedTactic]`, `highest_severity`, `evidence_spans: List[EvidenceSpan]` | 23 canonical scam tactics mapped to declarative regex patterns with negative contextual guards. |
| **Phase 7** | Semantic Similarity & Novelty | `src/semantic/` (`analyzer.py`, `embedder.py`, `reference_index.py`, `novelty.py`), `data/semantic/reference/` | Input: text string. Output: `SemanticResult` (`max_similarity`, `novelty_score`, `nearest_neighbors`, `provisional_novelty_flag`) | Uses offline `sentence-transformers/all-MiniLM-L6-v2` against 500 training references. |
| **Phase 8** | Risk Aggregation Pipeline | `src/aggregation/` (`pipeline.py`, `aggregator.py`, `schemas.py`) | Input: `CaseAssessmentInput`. Output: `CaseAssessmentResult` (`status`: `likely_scam`, `mixed_signals`, `likely_non_scam`, ledger, rules triggered) | Multi-signal deterministic decision matrix; strict audit ledger. |
| **Phase 9A** | OCR Ingestion Adapter | `src/ocr/` (`extractor.py`, `ocr_engine.py`) | Input: Image path/bytes. Output: `OCRResult` with raw text, normalized text, engine status | Fixture fallback ensures determinism and offline reproducibility without native Tesseract. |
| **Phase 9B** | Visual Classification | `src/vision/` (`image_classifier.py`), `data/visual/` | Input: Image file. Output: `VisualClassificationResult` | Experimental baseline for non-textual layout indicators. |
| **Phase 10** | RAG & Grounded Explanation | `src/rag/`, `src/explanation/` | Input: `CaseAssessmentResult`. Output: `ExplanationResult` with grounded narrative and cited evidence IDs | LLM acts purely as explainer; strictly grounded in Phase 8 ledger; zero hallucination. |
| **Phase 11** | Investigation Service & UI | `src/app/` (`service.py`, `cli.py`, `streamlit_app.py`) | Input: `InvestigationInput` (text, image, URLs). Output: `InvestigationReport` | Coordinates multi-modal analysis into unified case report. |
| **Phase 12** | Generalization Benchmark | `src/evaluation/phase12/`, `data/evaluation/phase12/` | Benchmark suites: `real_world`, `modern_scam_patterns`, `hard_negatives`, `multilingual`, `obfuscated`, `novel_patterns`, `urls`, `screenshots` | Formal measurement of baseline gaps; frozen reference reports. |

---

## 3. Generalization Gaps Identified in Phase 12

The frozen evaluation in Phase 12 established the following baseline results on the consolidated test distribution:

1. **Native Devanagari Hindi (`hi`)**:
   - Baseline Recall: **0.00%** (0 of 5 detected).
   - Word TF-IDF OOV Rate: **100.0%**.
   - Root Cause: Phase 3 regex token pattern `(?u)\b\w\w+\b` and English vocabulary completely ignore or drop non-Latin script tokens.
2. **Romanized Hinglish (`hi-Latn`)**:
   - Baseline Recall: **33.33%** (3 of 9 detected).
   - Root Cause: Phonetic transliterations ("aapka account band ho jayega", "turant sampark karein") share zero n-grams with English formal banking/lottery terms.
3. **Modern Indian Scam Modalities**:
   - Baseline Recall: **40.00%** (8 of 20 detected).
   - Root Cause: Emerging pretexts (Digital Arrest, Electricity Bill Cutoff, KYC Pan update, Part-Time Telegram Task) use modern vernacular and communication platforms absent from the 2011 UCI dataset.
4. **Obfuscation Sensitivity**:
   - Controlled Pair Label Flip Rate: **10.0%**.
   - Obfuscated Recall: **20.0%** (2 of 10 detected).
   - Root Cause: Word-boundary TF-IDF fails when characters are spaced (`S B I`), substituted with leetspeak (`b10cked`), or padded with emojis/symbols.
5. **Hard Negative Discrimination**:
   - Baseline Hard-Negative False Positive Rate: **7.69%** (1 of 13 benign cases incorrectly flagged).
   - Root Cause: Lexical models trigger on isolated keywords like "OTP", "urgent", or "bank" regardless of benign transactional context.

---

## 4. Phase 13 Experimental Architecture

Phase 13 introduces an isolated, additive experimental layer without disturbing existing Phase 1–12 production code:

```text
                                  Incoming Message (Text / Image OCR)
                                                   │
                                                   ▼
                                      Deterministic Preprocessing
                                                   │
                        ┌──────────────────────────┼──────────────────────────┐
                        ▼                          ▼                          ▼
               Text Representations          Tactic Engine               URL Scanner
               ├── Model A: Word TF-IDF      └── 23 Rules                └── 14 Structural
               │   (Frozen Baseline)             (Evidence Spans)            Signals
               ├── Model B: Char/Subword
               │   TF-IDF (char_wb (3,5))
               ├── Model C: Offline Semantic
               │   Embedding (MiniLM-L6)
               └── Model D: Hybrid Fusion
                        │                          │                          │
                        └──────────────────────────┼──────────────────────────┘
                                                   ▼
                                      Phase 13 Experimental Classifier
                                                   │
                                                   ▼
                                     Novelty & Unknown Threat Layer
                                                   │
                                                   ▼
                                 Multi-Signal Forensic Risk Aggregation
                                                   │
                                                   ▼
                                     Grounded Ledger & Explanation
```

### Proposed Experimental Models in `src/models/phase13/`:
1. **Model A (Frozen Baseline Control)**:
   - Reuses `src/models/baseline_classifier.py` with threshold 0.30.
2. **Model B (Subword / Character n-gram TF-IDF + Logistic Regression)**:
   - Analyzer: `char_wb` (character n-grams within word boundaries).
   - n-gram range: `(3, 5)`.
   - Normalization: Unicode NFKC normalization prior to tokenization.
   - Purpose: Mitigates spacing obfuscation, leetspeak, inflected Hinglish, and Devanagari Unicode character sequences.
3. **Model C (Offline Semantic Representation + Logistic Regression)**:
   - Vectorizer: Sentence transformer (`sentence-transformers/all-MiniLM-L6-v2`) cached locally.
   - Purpose: Tests whether dense semantic embeddings improve cross-lingual and paraphrase generalization without online calls.
4. **Model D (Tactic-Aware Hybrid Fusion)**:
   - Feature vector: Concatenation of Subword Text Features + Phase 6 Tactic Indicator Vector (23 binary/frequency flags) + Phase 4 URL Risk Signals (14 binary flags).
   - Purpose: Investigates whether combining behavioral tactics with lexical evidence prevents false positives and improves detection of modern multi-vector scams.

---

## 5. Dataset Architecture & Leakage Safeguards

### Dataset Location: `data/evaluation/phase13/`
Subdirectories:
- `training/`: Training split for experimental models.
- `validation/`: Validation split strictly used for model selection and threshold calibration (thresholds tested: [0.10, 0.20, 0.30, 0.40, 0.50, 0.60]).
- `test/`: Final test split held out until model evaluation.
- `hard_negatives/`: Expanded benign set with scam-like urgency, OTPs, and bank alerts.
- `multilingual/`: Balanced Native Hindi (`hi`) and Romanized Hinglish (`hi-Latn`) samples.
- `obfuscation/`: Paired original vs. syntactically perturbed messages sharing identical `pattern_group_id`.
- `novel_patterns/`: Emergent threat patterns (Digital Arrest, AI Voice Cloning, Fake Customs, Part-Time Telegram).

### Schema Contract for Phase 13 Samples:
Every sample must contain:
1. `sample_id` (string, unique)
2. `text` (string)
3. `label` (`scam` or `non_scam`)
4. `language` (`en`, `hi`, `hi-Latn`)
5. `scam_category` (string)
6. `tactics` (list of strings)
7. `evidence_spans` (list of dicts)
8. `source_reference` (string)
9. `collection_date` (ISO date string)
10. `pattern_group_id` (string)
11. `known_unknown_status` (`known_pattern` or `novel_pattern`)
12. `provenance_type` (`human_curated` or `synthetic`)
13. `phase13_source` (string)
14. `augmentation_type` (`none`, `leetspeak`, `spacing`, `punctuation`, `emoji`)
15. `language_family` (`Indo-European`, `Germanic`, etc.)
16. `script` (`Latin`, `Devanagari`)
17. `obfuscation_type` (`none`, `spacing`, `leetspeak`, `symbol_injection`)

### Leakage Invariant:
- Stratified group-level splitting by `pattern_group_id`.
- Augmented variants of any sample **must never cross split boundaries** (must remain in the same split as the parent pattern).
- Zero exact, zero normalized, and zero pattern-group overlap between `training`, `validation`, and `test` splits.

---

## 6. Audit Conclusion & Next Steps

All foundational modules (Phases 1–12) have been audited and verified intact. No existing files in `models/baseline/`, `data/evaluation/phase12/`, or `src/models/baseline_classifier.py` will be modified or overwritten.

We proceed to **Step 2 (Dataset Expansion)** and **Step 3 (Multilingual & Character Model Implementation)** under `data/evaluation/phase13/` and `src/models/phase13/`.
