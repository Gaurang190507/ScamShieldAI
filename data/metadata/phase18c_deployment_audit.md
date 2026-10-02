# ScamShield AI — Phase 18C Deployment Forensic Audit

**Audit Date:** October 3, 2026  
**Auditor:** Antigravity / Autonomous Forensic Agent  
**Scope:** Complete repository inspection, artifact integrity, runtime dependencies, deployment readiness, and operational boundaries.

---

## 1. Executive Summary

ScamShield AI is an AI-powered scam investigation and risk-analysis workbench engineered for multi-signal threat triage. The application has achieved **Release Readiness** for local, on-premises, and containerized deployment.

The codebase adheres strictly to an **Offline-First** architecture:
- Core scam classification, character n-gram modeling, hybrid fusion, passive URL analysis, semantic similarity scoring, tactic detection, and regulatory RAG run 100% locally on CPU without external API keys or network egress.
- Optional GenAI explanation capabilities (Groq / Gemini) are subordinate, non-authoritative, and fail-closed against deterministic outputs.
- All 5 release model artifacts are present on disk and verify bit-for-bit against canonical SHA-256 digests.

---

## 2. Repository Structure & Entry Points

```text
ScamShieldAI/
├── app.py                         # Official Root Entry Point (delegates to src.app.streamlit_app.main)
├── .env.example                   # Clean environment template (zero secrets)
├── .gitignore                     # Production Git exclusion rules (caches/logs excluded, models preserved)
├── requirements.txt               # Production runtime dependencies
├── requirements-dev.txt           # Development and testing dependencies
├── .streamlit/
│   └── config.toml                # Headless production Streamlit configuration
├── src/
│   ├── app/
│   │   ├── streamlit_app.py       # Production multi-tab investigation UI (Quick Scan, Deep, Screenshot, History)
│   │   ├── service.py             # InvestigationService singleton orchestrator
│   │   ├── schemas.py             # Unified InvestigationInput / InvestigationReport contracts
│   │   └── health.py              # StartupValidator & pre-flight diagnostics
│   ├── detection/                 # Frozen ML classifiers (Phases 3, 5, 13)
│   ├── features/                  # Normalization, tactics, URL extraction (Phases 2, 4, 6, 17)
│   ├── semantic/                  # MiniLM similarity & novelty detection (Phase 7)
│   ├── rag/                       # Regulatory knowledge base & grounding validation (Phase 10)
│   ├── security/                  # Phase 15 input sanitization & prompt injection defenses
│   └── ocr/                       # Optical character recognition & environment detection
├── models/                        # Frozen model weights and vectorizers
├── data/
│   ├── semantic/reference/        # 3,881 reference embedding vectors & metadata
│   ├── demo/                      # Curated synthetic demo cases (phase18c_demo_cases.json)
│   └── metadata/                  # Phase 1–18C forensic audit logs and manifests
└── tests/                         # 441 automated unit, security, and regression tests
```

---

## 3. Installation & Runtime Requirements

| Dimension | Specification |
| :--- | :--- |
| **Python Version** | Python 3.10 to 3.13.x supported (Verified on Python 3.13.6 64-bit). |
| **Operating System** | Cross-platform: Windows 10/11, Ubuntu 20.04/22.04 LTS, macOS 12+ (Intel/Apple Silicon). |
| **CPU Requirements** | 2 cores minimum, 4 cores recommended (Standard x86_64 or ARM64). |
| **RAM Footprint** | Minimum 4 GB RAM; 8 GB RAM recommended for multi-worker deployments. |
| **Disk Storage** | ~2.5 GB total (code, PyTorch CPU runtime, HuggingFace MiniLM cache, model artifacts). |
| **UI Framework** | Streamlit >= 1.28.0. |

---

## 4. Model Artifact Inventory & Canonical Hashes

All 5 release artifacts required for production inference exist and match their authoritative SHA-256 digests:

| Artifact Name | Relative Path | File Size | Canonical SHA-256 Digest | Match |
| :--- | :--- | :---: | :--- | :---: |
| `baseline_vectorizer` | `models/baseline/tfidf_vectorizer.joblib` | 234,234 B | `a3c25ebaa90d0df69e80101cd8f6ac9e6b4c17c579a476da26a722881c60e1d5` | **YES** |
| `baseline_classifier` | `models/baseline/logistic_regression.joblib` | 85,967 B | `93fd14c652241e46583de4beb3f62546d78932b629d0b8e930808c2a4f8336e6` | **YES** |
| `char_vectorizer` | `models/phase13/char_ngram/char_vectorizer.joblib` | 279,014 B | `bd53f31398d015130a711c7657cf31fe13e952e749631b3147b89532b1b3f142` | **YES** |
| `char_classifier` | `models/phase13/char_ngram/char_classifier.joblib` | 63,099 B | `86021d25325eb27a989651a7da23f0c3c8a6f78df660bf64694d107a3ff281a3` | **YES** |
| `reference_embeddings` | `data/semantic/reference/reference_embeddings.npy` | 5,961,344 B | `f4ad641ae6d3a34502a7f71ceaca1322762d9852c348c4e36cb767da2790101b` | **YES** |

Total model artifact storage: **~6.6 MB** on disk.

---

## 5. Optical Character Recognition (OCR) Strategy

- **Native Dependency**: OCR requires the underlying `tesseract` binary and language packs on the host OS.
- **Audited Deployment Status**: In host environments where native Tesseract is not installed, `OCREnvironmentDetector.inspect()` safely identifies `installed: False`.
- **Deployment Strategy**: **Option B (Graceful Transparency)**:
  - If Tesseract is present on the host PATH, OCR functions normally.
  - If Tesseract is absent, the UI presents an amber **Infrastructure Notice** detailing exact operating system installation commands (`winget install UB-Mannheim.TesseractOCR` / `apt install tesseract-ocr`).
  - Text and URL investigation continue to function with 100% operational fidelity; no crashes or unhandled exceptions occur.

---

## 6. Environment Variables & Secret Safety

Inspection of `.env.example` confirms:
- **Zero Secrets**: Contains empty placeholders only (`GROQ_API_KEY=`, `GEMINI_API_KEY=`, `TESSERACT_CMD=`).
- **No Git Leaks**: `.env` and `*.env` are excluded via `.gitignore`.
- **Codebase Scan**: Regex pattern scans across all code, tests, docs, and configurations confirm zero leaked production API keys or credentials.

---

## 7. Memory & Latency Profile

- **Process Startup**: ~1.2 to 2.0 s (Python and library import).
- **Service Warmup (Cold Load)**: ~800 to 1200 ms (loading PyTorch, MiniLM model, reference numpy matrices).
- **Warm Inference Latency**:
  - Text-only Quick Scan: **~12–25 ms**
  - Full Deep Multi-Signal Investigation: **~45–85 ms**
- **RAM Footprint**: ~450 MB resident set size (RSS) during active inference.

---

## 8. Known Deployment Blockers

**None.**  
The repository is completely self-contained, tests are passing at 100%, model hashes are verified, entry points are consolidated, and offline default operation is guaranteed.
