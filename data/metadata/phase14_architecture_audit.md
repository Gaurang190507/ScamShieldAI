# ScamShield AI — Phase 14 Architecture & Engineering Audit

**Audit Date**: October 2026  
**Auditor**: ScamShield AI Production Engineering  
**Scope**: Complete repository architecture, runtime pipeline, model loading, memory management, configuration, logging, exception handling, security, and reproducibility.  
**Governing Principle**: Zero alterations to frozen models (Phases 1–13), zero threshold tuning, zero network dependencies by default.

---

## Executive Summary

This architecture audit evaluates the complete ScamShield AI system transitioning from experimental research (Phases 1–13) to production-oriented engineering (Phase 14). The repository contains robust, leakage-free forensic detection components across multiple modalities (text, URL, tactics, semantics, OCR, visual layout). However, current runtime orchestration exhibits several engineering weaknesses:
1. Absence of a centralized, immutable configuration management layer (paths and thresholds scattered across modules).
2. Lack of process-level singleton model caching for expensive PyTorch transformer weights (`all-MiniLM-L6-v2`), causing repeated loading and latency spikes.
3. Lack of artifact integrity validation (no checksum or metadata schema verification prior to unpickling).
4. Unbounded input sizes (no defensive guards against oversized text, excessive URL counts, or image decompression bombs).
5. Unstructured logging (ad-hoc prints and warning lists without structured forensic audit logging or PII sanitization).
6. Inconsistent exception boundaries (optional components like RAG and visual features degrade gracefully, but core pipeline stages lack defensive isolation).

This document details all 20 audit criteria required by Phase 14 specifications.

---

## 1. Current Application Entry Points

The repository exposes three primary application entry points:

1. **Command-Line Interface (CLI)**:
   - File: `src/app/cli.py` (`main()` function)
   - Functionality: Argument parser accepting `--text`, `--url`, `--image`, `--provider`, `--top-k`, and `--json`.
   - Behavior: Instantiates a new `InvestigationService(default_provider=args.provider)` per invocation, constructs `InvestigationInput`, runs `service.investigate()`, and prints formatted Markdown or serialized JSON to stdout.
   - Exit Codes: Returns 1 on empty input arguments, 0 on successful investigation.

2. **Streamlit Interactive Console (UI)**:
   - File: `src/app/streamlit_app.py` (`main()` function)
   - Functionality: Multi-modal forensic investigation console with sidebar privacy controls.
   - Behavior: Uses `@st.cache_resource` on `get_investigation_service()` to maintain a single service instance per server worker. Provides text area, URL input, and file uploader for screenshots. Renders risk badge, metric cards, 5 multi-signal forensic tabs, Phase 10 grounded explanation, and Markdown/JSON export buttons.

3. **Programmatic Python Investigation API**:
   - File: `src/app/service.py` (`InvestigationService.investigate()`)
   - Functionality: High-level Python facade orchestrating input validation, temporary file lifecycles, OCR extraction, visual features, multi-signal pipeline analysis, grounded explanation, and forensic audit compilation.
   - Schemas: Consumes `InvestigationInput` and outputs canonical `InvestigationReport`.

---

## 2. Current Inference Flow

The end-to-end execution path through `InvestigationService.investigate()` follows this sequential workflow:

```text
User Input (text, url, image_bytes, image_path)
    │
    ▼
1. Input Handling & Temp File Lifecycle
    - If image_bytes: writes to tempfile.NamedTemporaryFile
    - Detects input modality (empty, text_only, url_only, image_only, combined_all, etc.)
    - Returns early with safe empty report if no input provided
    │
    ▼
2. Modality-Specific Feature Extraction
    - Image present:
        * Phase 9A OCR extraction via AutoOCREngine (falls back gracefully to FixtureOCREngine or reports engine_unavailable)
        * Conservative text normalization and entity extraction (URLs, phones, emails, currency, OTP)
        * Phase 9B visual layout & heuristic feature extraction via VisualPredictor
    - URL aggregation:
        * Combines explicit URL + URLs parsed from text + URLs discovered in OCR
    - Text aggregation:
        * Combines explicit user text + normalized OCR text
    │
    ▼
3. Multi-Signal Detection Layer (CaseAssessmentPipeline.analyze)
    - Phase 4 URL Scanner: Passive structural analysis (heuristic risk scores, IP hosts, suspicious TLDs, entropy)
    - Phase 6 Tactic Detector: 23 declarative regex rules with grounded text spans and severity levels
    - Phase 3/13 Text Classifier: TF-IDF + Logistic Regression inference (scam probability & label)
    - Phase 7 Semantic Similarity: TextEmbedder encodes text -> cosine search in SemanticReferenceIndex -> novelty score
    │
    ▼
4. Deterministic Risk Aggregation (Phase 8 RiskAggregator.aggregate)
    - Evaluates priority conflict rules, hard scam indicators, corroboration rules, and hard negative patterns
    - Produces immutable verdict (likely_scam, likely_non_scam, mixed_signals, insufficient_evidence)
    │
    ▼
5. Evidence-Grounded Explanation (Phase 10 ExplanationGenerator.generate_report)
    - KnowledgeRetriever searches authoritative regulatory guidance chunks via TF-IDF cosine similarity
    - Invokes configured provider (Mock, Groq, Gemini)
    - GroundingValidator verifies evidence citations [CASE:...] and knowledge citations [KB:...]
    - On provider failure: gracefully falls back to deterministic summary template without losing verdict
    │
    ▼
6. Forensic Audit Trail & Report Generation
    - Compiles InvestigationReport with execution timestamps, modality flags, and zero-network audit guarantees
    - Cleans up temporary image files in finally block
```

---

## 3. Model-Loading Locations

Model and vectorizer loading is distributed across seven separate files:

| Component | File | Artifacts Loaded | Loader Method |
| :--- | :--- | :--- | :--- |
| **Phase 3 Baseline Classifier** | `src/models/baseline_classifier.py` | `models/baseline/tfidf_vectorizer.joblib`<br>`models/baseline/logistic_regression.joblib`<br>`models/baseline/model_metadata.json` | `joblib.load()`, `json.load()` |
| **Phase 13 Model B (Char n-gram)** | `src/models/phase13/char_classifier.py` | `models/phase13/char_ngram/char_vectorizer.joblib`<br>`models/phase13/char_ngram/char_classifier.joblib`<br>`models/phase13/char_ngram/metadata.json` | `joblib.load()`, `json.load()` |
| **Phase 13 Model C (Hybrid Fusion)** | `src/models/phase13/hybrid_fusion.py` | `models/phase13/hybrid_fusion/hybrid_vectorizer.joblib`<br>`models/phase13/hybrid_fusion/hybrid_scaler.joblib`<br>`models/phase13/hybrid_fusion/hybrid_classifier.joblib` | `joblib.load()`, `json.load()` |
| **Phase 13 Model D (Semantic Dense)** | `src/models/phase13/semantic_classifier.py`| `models/phase13/semantic_dense/semantic_classifier.joblib`<br>`models/phase13/semantic_dense/metadata.json` | `joblib.load()`, `json.load()` |
| **Phase 7 Semantic Embedder** | `src/semantic/embedder.py` | `sentence-transformers/all-MiniLM-L6-v2` | `SentenceTransformer()` |
| **Phase 7 Reference Index** | `src/semantic/reference_index.py` | `data/semantic/reference/reference_embeddings.npy`<br>`data/semantic/reference/reference_items.jsonl` | `np.load()`, `json.loads()` |
| **Phase 9B Visual Classifier** | `src/vision/visual_classifier.py` | `models/visual/visual_scaler.joblib`<br>`models/visual/visual_classifier.joblib` | `joblib.load()` |

---

## 4. Duplicate Initialization

1. **Per-Invocation Service Construction**:
   - In `cli.py`, every execution creates `InvestigationService()`, which instantiates `CaseAssessmentPipeline`, `OCRTextExtractor`, `VisualPredictor`, `ExplanationGenerator`, and `URLScanner`.
2. **Cascading Semantic Model Creation**:
   - Inside `CaseAssessmentPipeline.__init__`, if `semantic_analyzer` is not pre-supplied, it calls `SemanticReferenceIndex.load()`, which reads the 3,881 reference embeddings from disk. It then creates a `SemanticAnalyzer`, which instantiates a new `TextEmbedder`.
3. **Repeated Knowledge Base Indexing**:
   - Inside `ExplanationGenerator.__init__`, if `retriever` is not pre-supplied, it creates a new `KnowledgeRetriever()`. This reads all `.md` files in `data/knowledge/`, re-chunks them, and re-fits scikit-learn's `TfidfVectorizer` on the chunks.
4. **Test Suite Multi-Instantiation**:
   - Across the 36 test modules, hundreds of test cases instantiate fresh instances of `CaseAssessmentPipeline` or `TextEmbedder`, resulting in redundant weight loading.

---

## 5. Repeated Preprocessing

1. **Redundant URL Extraction**:
   - `InvestigationService.investigate` extracts URLs from the input text via `self.url_scanner.extract_urls(input_data.text)`. When passed to `pipeline.analyze(urls=combined_urls)`, the pre-extracted list is used; however, if called independently, `pipeline.analyze` re-runs `extract_urls`.
2. **Multiple Text Normalization Passes**:
   - Text is normalized in `OCRTextExtractor.extract` via `normalize_ocr_text`.
   - Text is again normalized in `CharNgramClassifier` via `normalize_unicode`.
   - Text is separately normalized in `TacticDetector` and `BaselineTextClassifier`.
   - While each normalization is fast and idempotent, consolidating a normalized representation early in the runtime pipeline avoids redundant Unicode and regex passes.

---

## 6. Expensive Operations

1. **SentenceTransformer Neural Inference (`TextEmbedder.embed_text`)**:
   - Performs a 6-layer MiniLM forward pass on CPU. Execution latency is 15–30 ms per message.
   - Cold initialization of the PyTorch execution context and weights takes 500–1,500 ms.
2. **Dense Cosine Similarity Matrix Search (`SemanticReferenceIndex.search`)**:
   - Performs a 1D-to-2D matrix multiplication (`(1, 384) x (3881, 384).T`). While highly optimized in NumPy BLAS (~0.5–1 ms), array allocation occurs on every call.
3. **Tesseract OCR Subprocess/Execution (`TesseractOCREngine.extract_text`)**:
   - When native Tesseract is installed, raster image processing can take 200–800 ms per image.
4. **Dynamic Knowledge Chunker & Vectorizer Fit (`KnowledgeRetriever.__init__`)**:
   - Iterates through the filesystem, parses markdown, splits sections, and fits an in-memory TF-IDF vocabulary.

---

## 7. Unnecessary Filesystem Operations

1. **Temporary Image Disk Writes**:
   - When an image is provided as raw bytes (e.g., via Streamlit file upload or programmatic API), `InvestigationService` writes it to disk using `tempfile.NamedTemporaryFile` and passes the path to `OCRTextExtractor` and `VisualPredictor`, which then re-open and decode the file from disk using PIL.
2. **Repeated Disk Reads for Reference and Knowledge Bases**:
   - `reference_items.jsonl` (3,881 lines) and `reference_embeddings.npy` (6.0 MB) are read from disk whenever `SemanticReferenceIndex.load()` is invoked without a cache.
   - Regulatory markdown files in `data/knowledge/` are re-read and tokenized on every un-cached `KnowledgeRetriever` instantiation.

---

## 8. Repeated Semantic-Model Loading

- In `src/semantic/embedder.py`, `TextEmbedder` lazily initializes `self._model` as an instance attribute.
- Because `self._model` is attached to the instance and not the process or class, every new `TextEmbedder()` instance reloads `SentenceTransformer('sentence-transformers/all-MiniLM-L6-v2')`.
- This causes PyTorch to reload weights from disk into host RAM repeatedly during test runs (observed as repeated `Loading weights: 100%` logs during test discovery).
- **Required Fix**: Introduce a thread-safe process-level singleton cache for `TextEmbedder._model` or `TextEmbedder` instances.

---

## 9. Repeated RAG Initialization

- `KnowledgeRetriever` (`src/rag/retriever.py`) does not cache the parsed `KnowledgeChunk` list or fitted `RetrievalIndex`.
- Whenever `ExplanationGenerator()` is instantiated with `retriever=None`, the knowledge base is reloaded and re-indexed.
- **Required Fix**: Implement a process-level singleton or cached factory for `KnowledgeRetriever` so that the knowledge corpus is parsed and indexed exactly once per process.

---

## 10. Configuration Scattered Through Source Code

Currently, configuration constants are hardcoded across multiple disjoint modules:
- Model directory paths: `models/baseline/`, `models/phase13/char_ngram/`, `models/semantic/` are hardcoded in `src/aggregation/pipeline.py`, `src/models/baseline_classifier.py`, and `src/models/phase13/char_classifier.py`.
- Reference corpus paths: `data/semantic/reference/` hardcoded in `src/aggregation/pipeline.py`.
- Knowledge base directory: `data/knowledge/` hardcoded in `src/rag/document_loader.py`.
- Decision thresholds:
  * Baseline Phase 3 threshold `0.30` hardcoded in `pipeline.py` and `baseline_classifier.py`.
  * Phase 13 Model B threshold `0.55` hardcoded in evaluation scripts and `char_classifier.py`.
- Retrieval parameters: `top_k=5` hardcoded in `pipeline.py`, `top_k=3` hardcoded in `cli.py` and `service.py`.
- **Required Fix**: Establish a centralized `src/config/runtime_config.py` separating **immutable frozen model thresholds** from **configurable runtime parameters** (cache settings, input bounds, logging levels).

---

## 11. Logging Weaknesses

1. **No Standardized Application Logger**:
   - The system primarily uses `print()` calls in evaluation scripts and internal `warnings: List[str]` in data schemas.
   - No unified `logging.Logger` hierarchy (`scamshield.pipeline`, `scamshield.service`, `scamshield.security`).
2. **Missing Operational Telemetry**:
   - No structured logs recording investigation start, pipeline stage execution, per-stage latency, or component availability.
3. **Absence of PII/Secret Masking**:
   - No centralized log filter ensuring raw user messages, passwords, OTPs, or API keys (`GROQ_API_KEY`, `GEMINI_API_KEY`) are masked before being emitted.
4. **Required Fix**: Implement structured application logging with correlation IDs, execution timings, and automated PII/secret redaction.

---

## 12. Exception-Handling Weaknesses

1. **Unprotected Core Pipeline Stages**:
   - In `CaseAssessmentPipeline.analyze()`:
     * Phase 7 semantic failure is caught and handled gracefully (`except Exception: top1_sim = None`).
     * However, Phase 3 classifier, Phase 4 URL analysis, and Phase 6 tactic detection are NOT wrapped in defensive try/except blocks. An unexpected error in these components would abort the entire investigation.
2. **No Differentiation Between Hard Failures and Optional Component Failures**:
   - `InvestigationService` catches visual and explanation errors, but if `CaseAssessmentPipeline.analyze()` throws any exception, `investigate()` crashes without generating a diagnostic report.
3. **Required Fix**: Wrap each distinct pipeline stage in structured error handling so that if any optional or secondary stage fails, the deterministic assessment produces partial findings with clear audit warnings rather than crashing.

---

## 13. Temporary-File Handling

1. **Potential Temp File Leakage**:
   - In `InvestigationService.investigate()`, temporary files are created using `tempfile.NamedTemporaryFile(delete=False)`. While cleaned up in `finally:`, an abrupt process termination (e.g., `SIGKILL`, unhandled OS signal) can leave orphaned files in the system temporary directory.
2. **Unnecessary Disk I/O for Bytes**:
   - Image bytes from Streamlit or API calls can be processed directly in-memory using `io.BytesIO` by image validators and PIL, avoiding temporary file creation altogether when path references are not strictly required.
3. **Required Fix**: Support direct in-memory stream processing where possible and implement safe context-managed temporary file wrappers with dedicated directory tracking.

---

## 14. Memory-Heavy Operations

1. **PyTorch Runtime Overhead**:
   - `SentenceTransformer` allocates ~400–600 MB RSS for PyTorch runtime libraries, CUDA stubs (even on CPU), and model weights.
2. **Reference Corpus Memory**:
   - 3,881 embeddings (shape `(3881, 384)`, `float32`) take 6.0 MB in contiguous RAM. However, the accompanying Python object list (`reference_items: List[ReferenceItem]`) with strings and metadata consumes ~25 MB of heap.
3. **Unbounded Image Allocation (Decompression Bombs)**:
   - Pillow's `Image.open()` on an unconstrained image could allocate hundreds of megabytes if an attacker uploads a huge image (e.g. 10,000 x 10,000 pixels).
4. **Required Fix**: Enforce `Image.MAX_IMAGE_PIXELS` and explicit width/height/file-size boundary checks prior to image decoding.

---

## 15. Serialization/Deserialization Behavior

1. **Unvalidated `joblib.load()`**:
   - Model files (`.joblib`) are deserialized directly via `joblib.load()` without prior verification of file size, SHA-256 integrity checksums, or schema version metadata.
   - Python's `pickle`/`joblib` deserializes arbitrary code; loading corrupted or altered files poses severe security and stability risks.
2. **Missing Schema Version Tags**:
   - Output dictionaries and serialized artifacts lack explicit `schema_version` markers to detect backwards incompatibility.
3. **Required Fix**: Create an artifact validation layer that verifies existence, file size, SHA-256 checksums, and metadata compatibility before loading.

---

## 16. Startup Latency Risks

1. **Cold Initialization Delays**:
   - Eagerly loading the baseline classifier, character model, SentenceTransformer, reference index, and knowledge retriever on application startup would result in a 3–5 second startup delay.
2. **Warm Latency Tradeoff**:
   - Pure lazy loading eliminates startup delay but introduces latency jitter for the first user query (up to 1.5 seconds for cold embedding inference).
3. **Required Strategy**: Use controlled lazy loading with thread-safe singleton caching, plus an optional explicit pre-warm method (`InvestigationService.warmup()`) for production deployments that require sub-50ms initial latency.

---

## 17. Inference Latency Risks

1. **Cold Embedding Forward Pass**:
   - The first call to `TextEmbedder.embed_text` on CPU takes ~1,000 ms due to PyTorch threadpool allocation and kernel caching. Subsequent calls take ~20 ms.
2. **Repeated Knowledge Corpus Fitting**:
   - Fitting `TfidfVectorizer` on markdown chunks during every un-cached request adds 25–50 ms of avoidable latency.
3. **Measured Baseline**:
   - Deterministic warm inference (Phases 3 + 4 + 6 + 7 + 8) currently runs in ~25–40 ms when models are pre-loaded in memory.

---

## 18. Reproducibility Risks

1. **Deterministic Components**:
   - Phases 3, 4, 6, 7, 8, 9A, 9B, and 13 are fully deterministic: given identical text, URLs, or images, the pipeline outputs identical probability scores, extracted spans, and risk verdicts across runs.
2. **Generative Explanation Variability**:
   - Phase 10 LLM generation via live external APIs (`groq`, `gemini`) is inherently non-deterministic.
   - The system correctly isolates this variability: the deterministic verdict is computed first, and the LLM explanation is constrained by post-generation grounding validation.
   - In default `mock` provider mode, Phase 10 is 100% deterministic and reproducible.

---

## 19. Dependency / Version Risks

1. **Installed Dependency Audit**:
   - `requirements.txt` specifies core dependencies:
     * `numpy>=1.24.0` (Active: `2.4.1`)
     * `pandas>=2.0.0` (Active: `3.0.0`)
     * `regex>=2023.8.8` (Active: `2026.9.29`)
     * `scikit-learn>=1.3.0` (Active: `1.9.1`)
     * `joblib>=1.3.0` (Active: `1.6.0`)
     * `torch>=2.2.0` (Active: `2.14.1`)
     * `sentence-transformers>=3.0.0` (Active: `6.1.0`)
     * `pytest>=7.4.0`
2. **Missing Explicit Requirements**:
   - `Pillow` (Active: `12.1.0`) and `streamlit` (Active: `1.61.1`) are required by `src/ocr/`, `src/vision/`, and `src/app/`, but were missing from `requirements.txt`.
3. **Cross-Version Pickle Warnings**:
   - `scikit-learn 1.9.1` emits `InconsistentVersionWarning` if models were saved under earlier minor releases. The validation layer must account for this cleanly.

---

## 20. Security-Sensitive Engineering Risks

1. **Network Invariant Enforcement**:
   - ScamShield AI must operate with **zero outbound network calls** and **zero DNS resolution** by default.
   - Passive URL analysis (`URLScanner`) must strictly analyze URL syntax, host IP patterns, TLDs, and entropy without issuing HTTP/HTTPS requests or socket queries.
2. **Input Flooding / ReDoS Protection**:
   - The tactic detector uses 23 regular expressions. If an attacker submits an excessively large payload (e.g., 5 MB string), regex evaluation could trigger excessive CPU consumption.
   - Defensive maximum text length limits (e.g., 50,000 characters) and URL length limits (e.g., 2,048 characters) must be strictly enforced.
3. **Decompression Bomb Protection**:
   - Image inputs must have strict dimension (e.g., max 4096 x 4096) and byte size (e.g., max 10 MB) boundaries before PIL decoding.
4. **Secret Redaction**:
   - Environment variables such as `GROQ_API_KEY` or `GEMINI_API_KEY` must never be logged, printed to stdout, or included in JSON export payloads.

---

## Conclusion & Action Plan for Phase 14

The audit confirms that the core detection capabilities across Phases 1–13 are sound, accurate, and completely leakage-free. To transition ScamShield AI into a production-grade system, Phase 14 will implement:

1. **Centralized Configuration (`src/config/runtime_config.py`)**:
   - Strict separation of immutable frozen model parameters from configurable runtime options.
2. **Artifact Management & Validation (`src/artifacts/manager.py`)**:
   - Existence, checksum, dimensionality, and metadata schema validation.
3. **Process-Level Model Cache (`src/artifacts/cache.py` or singleton manager)**:
   - Thread-safe caching for `SentenceTransformer`, vectorizers, reference index, and RAG index.
4. **Input Validation & Resource Limits (`src/security/guards.py`)**:
   - Bounds for text length, URL count, image dimensions, and payload sizes with clear error handling.
5. **Structured Logging & Masking (`src/observability/logging.py`)**:
   - Correlation IDs, stage timings, and automated PII/secret scrubbing.
6. **Resilient Pipeline Orchestration (`src/app/service.py`)**:
   - Defensive boundaries ensuring optional component failures never degrade the deterministic verdict.
7. **Comprehensive Profiling & Regression Verification**:
   - Benchmark cold vs. warm latency and verify that all 332 historical tests pass with 0 regressions.
