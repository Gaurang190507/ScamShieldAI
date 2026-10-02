# ScamShield AI — Phase 18A Repository Forensic Inventory

## 1. Executive Summary & Audit Scope

This document provides a comprehensive forensic inventory of the complete **ScamShield AI** repository as of Phase 18A (Final Architecture Audit & Production Cleanup).

- **Total Directories**: 38
- **Total Tracked Files**: 430+ files across source, data, models, tests, fixtures, and documentation.
- **Repository Health**: Clean, strictly modular, 100% test-passing architecture.
- **Immutability Status**: All historical artifacts across Phases 1 through 17 remain bit-for-bit immutable.

---

## 2. Directory Hierarchy & Phase Ownership

```text
ScamShieldAI/
├── .gitignore                      [Root] Git ignore definitions (ignores __pycache__, .env, models/* weights)
├── .env.example                    [Phase 18A] Production environment configuration template
├── README.md                       [Phase 1] Project overview and mission statement
├── requirements.txt                [Phase 1–18A] Production and development Python dependencies
├── app.py                          [Phase 18A Refactored] Root entry point delegating to production console
├── data/                           [Phases 1–17 Data & Metadata Repository]
│   ├── dataset/                    [Phase 1] Raw and processed UCI SMS corpora (spam_clean.csv, splits)
│   ├── embeddings/                 [Phase 7/14] Precomputed semantic embeddings and reference indices
│   ├── evaluation/                 [Phases 3–17] Historical evaluation reports, JSON results, benchmarks
│   │   ├── adversarial/            [Phase 15] Adversarial boundary evaluation data
│   │   ├── annotation_pilot/       [Phase 1] Pilot data annotation templates and guidelines
│   │   ├── baseline/               [Phase 3] Baseline TF-IDF + Logistic Regression benchmark reports
│   │   ├── char_ngram/             [Phase 13] Character n-gram evaluation metrics and reports
│   │   ├── hybrid/                 [Phase 5/13] Hybrid multimodal fusion evaluation data
│   │   ├── knowledge_base/         [Phase 10] RAG evaluation metrics
│   │   ├── ocr/                    [Phase 9A] OCR benchmark evaluations
│   │   ├── phase12/                [Phase 12] Frozen robustness evaluation reports
│   │   ├── phase13/                [Phase 13] Frozen generalization evaluation reports
│   │   ├── phase14/                [Phase 14] Frozen production optimization reports
│   │   ├── phase15/                [Phase 15] Frozen security architecture reports
│   │   ├── phase16/                [Phase 16] Immutable real-world validation benchmark reports
│   │   ├── phase17/                [Phase 17] Frozen failure remediation reports and errata
│   │   ├── semantic/               [Phase 7] Semantic similarity benchmarks
│   │   ├── tactics/                [Phase 6] Tactic detector rule evaluation benchmarks
│   │   ├── url_analysis/           [Phase 4] URL scanner benchmarks
│   │   └── visual/                 [Phase 9B] Visual feature classification benchmarks
│   ├── knowledge_base/             [Phase 10] 12 curated regulatory and advisory knowledge chunks (JSON)
│   ├── metadata/                   [Phases 1–18A] System specifications, audit records, schemas
│   ├── reference/                  [Phase 7] Curated reference texts and manifests
│   ├── semantic/                   [Phase 7/14] 3,881 reference items and 384-d NumPy embeddings
│   ├── splits/                     [Phase 1/3] Leakage-free train/validation/test splits
│   └── synthetic/                  [Phase 12/13] Synthetic seed datasets for stress-testing
├── fixtures/                       [Phase 9A/9B] Deterministic test images and metadata manifests
│   └── images/                     [Fixtures 01–05: scam, legitimate, payment, blank, edge_case]
├── models/                         [Phases 3, 5, 13 Frozen Model Artifacts]
│   ├── baseline/                   [Phase 3] tfidf_vectorizer.joblib, logistic_regression.joblib
│   ├── hybrid/                     [Phase 5] tfidf_vectorizer.joblib, logistic_regression.joblib, url_scaler.joblib
│   └── phase13/                    [Phase 13]
│       ├── char_ngram/             [Model B] char_vectorizer.joblib, char_classifier.joblib
│       ├── hybrid_fusion/          [Model D] hybrid_vectorizer.joblib, hybrid_classifier.joblib, scaler
│       └── semantic_dense/         [Model C] semantic_classifier.joblib
├── scratch/                        [Early Development] One-off exploratory scripts (evaluate_pilot, etc.)
├── scripts/                        [Evaluation Runners] run_phase17_evaluation.py
├── src/                            [Production Source Code]
│   ├── aggregation/                [Phase 8] Case assessment aggregator, pipeline, and normalizers
│   ├── app/                        [Phase 11/14] Unified service, schemas, CLI, and Streamlit console
│   ├── artifacts/                  [Phase 14] Thread-safe singleton model caching and artifact manager
│   ├── benchmark/                  [Phase 14] Profiling and microbenchmarking utilities
│   ├── config/                     [Phase 14] Immutable frozen model configs and runtime settings
│   ├── data/                       [Phase 1] Data loaders, validators, UCI SMS ingestion
│   ├── evaluation/                 [Phases 12, 13, 16] Evaluation runners and report generators
│   ├── explainability/             [Phase 1/2] Early prototype explainer (preserved for compatibility)
│   ├── explanation/                [Phase 10] RAG explanation generator, grounding gatekeeper, providers
│   ├── ml/                         [Phase 3] Machine learning helper routines
│   ├── models/                     [Phase 3, 13] BaselineTextClassifier and Phase 13 models (A, B, C, D)
│   ├── novelty/                    [Phase 7] Novelty estimation utilities
│   ├── observability/              [Phase 14] Structured JSON logging and PII redaction
│   ├── ocr/                        [Phase 9A, 17] Image loader, OCR engine adapters, environment detector
│   ├── phase17/                    [Phase 17] ObfuscationNormalizer, EmergingPatternAnalyzer
│   ├── preprocessing/              [Phase 2] Text cleaning, entity extraction, canonicalization
│   ├── rag/                        [Phase 10] TF-IDF knowledge retriever and chunk indexer
│   ├── risk_engine/                [Phase 1/2] Early prototype scoring engine (preserved for compatibility)
│   ├── rules/                      [Phase 1/2] Early prototype rule patterns (preserved for compatibility)
│   ├── security/                   [Phase 15] Defensive guards, path sanitization, prompt injection defense
│   ├── semantic/                   [Phase 7] TextEmbedder (MiniLM), SemanticReferenceIndex, SemanticAnalyzer
│   ├── similarity/                 [Phase 7] Cosine similarity routines
│   ├── tactics/                    [Phase 6, 17] TacticDetector (23 rules), ContextualTacticEnhancer
│   ├── url_analysis/               [Phase 4] URLScanner, URL parser, passive feature extraction
│   ├── utils/                      [Phases 1–14] Path and string utilities
│   └── vision/                     [Phase 9B] Visual feature extractor, layout classifier, VisualPredictor
└── tests/                          [Test Suites — 432 Tests, 100% Passing]
    ├── fixtures/                   [Test image fixtures and generator scripts]
    └── test_*.py                   [40 distinct test modules covering Phases 1 through 17]
```

---

## 3. Application Entry Points

ScamShield AI provides three distinct, unified application entry points:
1. **Interactive Web Console (Production)**:
   - File: [`src/app/streamlit_app.py`](file:///c:/Users/radika/OneDrive/Desktop/ScamShieldAI/src/app/streamlit_app.py) (and root [`app.py`](file:///c:/Users/radika/OneDrive/Desktop/ScamShieldAI/app.py) delegator).
   - Execution: `streamlit run app.py` or `streamlit run src/app/streamlit_app.py`.
   - Capabilities: Multi-modal ingestion (text, URL, screenshot upload), live assessment badges, evidence breakdowns, grounded RAG explanations, and report export.
2. **Forensic Command-Line Interface (CLI)**:
   - File: [`src/app/cli.py`](file:///c:/Users/radika/OneDrive/Desktop/ScamShieldAI/src/app/cli.py).
   - Execution: `python -m src.app.cli --text "..." --url "..." --image "..."`.
   - Capabilities: Full terminal-based forensic investigations with structured Markdown or raw JSON output.
3. **Application Service API**:
   - File: [`src/app/service.py`](file:///c:/Users/radika/OneDrive/Desktop/ScamShieldAI/src/app/service.py) (`InvestigationService`).
   - Contract: Takes `InvestigationInput` schema; returns `InvestigationReport` schema.

---

## 4. Frozen Model Artifacts & Cryptographic Verification

| Artifact Key | File Path | Phase Origin | Role | Authoritative SHA-256 |
|---|---|---|---|---|
| `baseline_vectorizer` | `models/baseline/tfidf_vectorizer.joblib` | Phase 3 | Word-level TF-IDF (1, 2) unigram/bigram | `a3c25ebaa90d0df69e80101cd8f6ac9e6b4c17c579a476da26a722881c60e1d5` |
| `baseline_classifier` | `models/baseline/logistic_regression.joblib` | Phase 3 | Logistic Regression (threshold: 0.30) | `93fd14c652241e46583de4beb3f62546d78932b629d0b8e930808c2a4f8336e6` |
| `char_vectorizer` | `models/phase13/char_ngram/char_vectorizer.joblib` | Phase 13 | Character n-gram TF-IDF (3, 5) | `bd53f31398d015130a711c7657cf31fe13e952e749631b3147b89532b1b3f142` |
| `char_classifier` | `models/phase13/char_ngram/char_classifier.joblib` | Phase 13 | Model B Logistic Regression (threshold: 0.55) | `86021d25325eb27a989651a7da23f0c3c8a6f78df660bf64694d107a3ff281a3` |
| `reference_embeddings` | `data/semantic/reference/reference_embeddings.npy` | Phase 7 | 3,881 x 384-d normalized embeddings | `f4ad641ae6d3a34502a7f71ceaca1322762d9852c348c4e36cb767da2790101b` |

---

## 5. Test Suite Accounting

The unified test suite consists of **432 passing tests** across 40 test files:
- **Historical Functional Tests (Phases 1–14)**: 359 tests (100% PASS)
- **Authoritative Security Suite (Phase 15)**: 40 tests in `tests/test_phase15_security.py` (100% PASS)
- **Historical Real-World Benchmark Tests (Phase 16)**: 6 tests in `tests/test_phase16_validation.py` (100% PASS)
- **Engineering Repair Suite (Phase 17)**: 27 tests in `tests/test_phase17_repair.py` (100% PASS)
- **Total Suite**: **432 / 432 PASS** (0 failures, 0 errors, 0 regressions)

---

## 6. Dead Code, Duplication, and Obsolete File Audit

1. **Root `app.py` vs `src/app/streamlit_app.py` (Resolved in Phase 18A)**:
   - Root `app.py` previously contained an outdated Phase 1/2 prototype that manually called primitive rule detectors and bypassed the entire modern `InvestigationService`.
   - Refactored `app.py` to cleanly delegate directly to `src.app.streamlit_app.main()`, providing a single unified entry point without duplicating pipeline logic.
2. **Early Phase 1/2 Modules (`src/rules/`, `src/risk_engine/`, `src/explainability/`)**:
   - These modules represent early development phases. They are maintained intact because `tests/test_placeholder.py` asserts their presence and contracts, preserving full historical backward-compatibility.
3. **Scratch Scripts (`scratch/`)**:
   - `scratch/evaluate_pilot.py`, `scratch/generate_phase12_dataset.py`, `scratch/inspect_pilot.py` are one-off diagnostic utilities from earlier research phases. They are non-executable in production runtime and are retained for forensic provenance.
4. **Configuration Cleanliness**:
   - Created `.env.example` to provide developers with a clear configuration template while preventing secret commits.
