# ScamShield AI — Phase 18A Dependency Audit

## 1. Audit Scope & Methodology

This audit examines all declared and imported dependencies within the ScamShield AI project to verify necessity, version constraints, security implications, and isolation boundaries.

- **Primary Manifest**: `requirements.txt`
- **Secondary Manifests**: None (clean single-manifest design)
- **Policy**: Zero unvetted dependencies; zero automatic upgrades; strict version pinning/bounding.

---

## 2. Dependency Classification Matrix

| Package Name | Specified Constraint | Classification | Primary Usage / Subsystem | Audit Status & Security Notes |
|---|---|---|---|---|
| `numpy` | `>=1.24.0` | **REQUIRED** | Array processing, cosine similarity, 3,881 x 384 embedding store | Essential runtime dependency. Zero network egress. |
| `pandas` | `>=2.0.0` | **REQUIRED** | Dataset ingestion (UCI SMS), split validation, manifest serialization | Core data manipulation library. Verified safe. |
| `regex` | `>=2023.8.8` | **REQUIRED** | Obfuscation normalization, Unicode homoglyphs, tactic pattern rules | Replaces standard `re` where atomic grouping & advanced Unicode properties are required. |
| `scikit-learn` | `>=1.3.0` | **REQUIRED** | TF-IDF vectorizers (word & char n-gram), Logistic Regression models | Frozen model deserialization and feature transformation. |
| `joblib` | `>=1.3.0` | **REQUIRED** | Model weight serialization and deserialization | Artifact loader. Validated via `ArtifactManager`. |
| `torch` | `>=2.2.0` | **REQUIRED** | Tensor execution for MiniLM sentence transformer | Local CPU inference backend. Confirmed offline execution. |
| `sentence-transformers` | `>=3.0.0` | **REQUIRED** | MiniLM-L6-v2 embedding generation (Phase 7, 10) | Local neural embeddings. Model weights pre-cached. |
| `Pillow` | `>=10.0.0` | **REQUIRED** | Image file loading, dimension checking, raster validation | Bounded dimensions (4096px) prevent decompression bombs. |
| `streamlit` | `>=1.28.0` | **REQUIRED** | Web-based forensic investigation console | Application UI. Isolated from core ML logic. |
| `psutil` | `>=5.9.0` | **REQUIRED** | Memory tracking, RSS telemetry, latency profiling (Phase 14) | System resource observability and leak detection. |
| `pytest` | `>=7.4.0` | **DEVELOPMENT ONLY** | Test execution framework | Used for CI/CD test automation. |
| `pytesseract` | *(Not in manifest)* | **OPTIONAL** | Local adapter for host Tesseract OCR binary | Soft dependency. Handled gracefully via `OCREnvironmentDetector` without crashing when missing. |

---

## 3. Dependency Findings & Recommendations

### 3.1 Unused or Redundant Dependencies
- **Audit Result**: Zero unused dependencies in `requirements.txt`. Every declared package corresponds to active production or evaluation imports in `src/`.

### 3.2 Missing Runtime Dependencies
- **Audit Result**: Zero missing runtime dependencies. The core test suite (432 tests) and runtime application run cleanly on standard Python 3.10–3.13 environments with only `requirements.txt` installed.

### 3.3 Optional OCR Dependency Handling (`pytesseract`)
- **Finding**: `pytesseract` is a Python wrapper around the system `tesseract` binary. It is deliberately treated as an optional soft dependency.
- **Classification**: **OPTIONAL / FUTURE REVIEW**.
- **Rationale**: If a user runs ScamShield AI without `pytesseract` or without the native C++ binary, `OCREnvironmentDetector` safely reports `ocr_available=False` and downstream stages proceed gracefully. Packaging `pytesseract` in `requirements.txt` without the underlying OS binary can cause confusion; documentation clearly instructs users to install both when OCR capability is required.

### 3.4 Development vs. Runtime Separation
- `pytest` is currently listed in `requirements.txt`.
- **Recommendation (Deferred Improvement)**: In future deployment phases (e.g. Docker containerization), separate into `requirements.txt` (runtime only) and `requirements-dev.txt` (`pytest`, linters). For Phase 18A, keeping `pytest` in `requirements.txt` maintains developer setup simplicity without introducing runtime overhead.
