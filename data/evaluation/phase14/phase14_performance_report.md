# ScamShield AI — Phase 14 Performance & Resource Report

**Evaluation Date**: October 2026  
**Auditor / Harness**: ScamShield AI Production Engineering (`src/benchmark/phase14_profiler.py`)  
**Status**: Real Empirical Measurements (Local Host Environment)

---

## 1. Environment & Hardware Information

| Parameter | Specification |
| :--- | :--- |
| **Operating System** | Windows 11 (10.0.26200-SP0) |
| **Python Runtime** | Python 3.13.6 (64-bit) |
| **Processor** | Intel64 Family 6 Model 140 Stepping 1 (4 logical cores) |
| **Total System RAM** | 7.65 GB |
| **Execution Mode** | 100% Offline (Local CPU Inference, 0 Network Calls) |
| **PyTorch Execution** | CPU Threadpool (Torch 2.14.1, MKL/BLAS) |
| **Native Tesseract Binary** | NOT INSTALLED (Reported accurately; uses `FixtureOCREngine` fallback) |

---

## 2. Cold-Start & Model Loading Latency

Cold loading measures the initial import and deserialization of model weights, vectorizer vocabularies, reference indices, and neural networks into process RAM.

| Component | Disk Artifacts | Cold Load Time (ms) | RSS RAM Delta (MB) |
| :--- | :--- | :---: | :---: |
| **Phase 3 Baseline Classifier** | `tfidf_vectorizer.joblib`<br>`logistic_regression.joblib`<br>`model_metadata.json` | 19.5 ms | +2.32 MB |
| **Phase 13 Model B (Char n-gram)** | `char_vectorizer.joblib`<br>`char_classifier.joblib`<br>`metadata.json` | 48.0 ms | +3.01 MB |
| **Phase 10 Knowledge Retriever** | `data/knowledge_base/*.json`<br>(Parsed chunks & fitted TF-IDF) | 51.0 ms | +0.18 MB |
| **Phase 7 Semantic Reference Index**| `reference_embeddings.npy`<br>`reference_items.jsonl` | 52.1 ms | +8.59 MB |
| **Phase 7 SentenceTransformer** | `all-MiniLM-L6-v2`<br>(PyTorch state dict & tokenizer) | 10,871.2 ms | +371.73 MB |
| **Total Process Resident Set Size** | Baseline process (163.2 MB) -> Fully loaded | — | **549.03 MB** |

### Key Finding:
The neural sentence embedder (`all-MiniLM-L6-v2`) accounts for **98.8% of cold initialization time** (10.87 seconds) and **96.3% of model memory footprint** (+371.7 MB). Without process-level caching, every pipeline instance would incur a ~10-second penalty.

---

## 3. Per-Stage Latency Distribution

Micro-benchmarked over 50 iterations on a realistic phishing payload containing manipulative urgency, account threat, and suspect URL:

| Pipeline Stage | Mean (ms) | Median (ms) | Min (ms) | Max (ms) | P95 (ms) | Primary Operational Cost |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: |
| **Phase 4 URL Analysis** | 1.10 ms | 0.89 ms | 0.69 ms | 3.72 ms | 1.66 ms | URL regex parsing, IP check, entropy |
| **Phase 6 Tactic Detection** | 0.64 ms | 0.50 ms | 0.35 ms | 1.37 ms | 1.27 ms | 23 declarative regex pattern searches |
| **Phase 3 Baseline Classifier** | 1.23 ms | 1.02 ms | 0.64 ms | 2.56 ms | 2.18 ms | TF-IDF sublinear transform + LR predict |
| **Phase 13 Char Classifier** | 1.27 ms | 1.00 ms | 0.70 ms | 2.66 ms | 2.43 ms | Subword char_wb (3,5) transform + LR |
| **Phase 7 Sentence Embedding** | 33.26 ms | 29.24 ms | 16.89 ms | 105.56 ms | 52.71 ms | 6-layer MiniLM transformer CPU inference |
| **Phase 7 Reference Search** | 0.58 ms | 0.55 ms | 0.45 ms | 1.08 ms | 0.78 ms | NumPy BLAS dot-product (1x384 vs 3881x384) |
| **Phase 10 RAG Retrieval** | 1.84 ms | 1.61 ms | 1.07 ms | 3.29 ms | 2.95 ms | TF-IDF cosine search over guidance chunks |
| **Phase 8 Risk Aggregation** | 0.12 ms | 0.10 ms | 0.08 ms | 0.31 ms | 0.19 ms | Deterministic priority conflict rules |

---

## 4. End-to-End Investigation Latency by Workload

Measured on an initialized **Warm Process** (pre-warmed via `service.warmup()`) across 20 warm iterations per workload using `InvestigationService` with all process caches enabled:

| Workload Description | Modality | Verdict | Evidence Items | First Investigation (ms)* | Warm Mean (ms) | Warm Median (ms) | Warm P95 (ms) |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| **Workload 1: Clean Benign Text** | Text only | `likely_non_scam` | 3 | 37.8 ms | **29.8 ms** | 25.5 ms | 39.0 ms |
| **Workload 2: Bank Phishing SMS + URL**| Text + URL | `likely_scam` | 10 | 31.0 ms | **32.3 ms** | 27.8 ms | 40.8 ms |
| **Workload 3: Suspicious URL Only** | URL only | `mixed_signals` | 9 | 26.5 ms | **32.0 ms** | 27.5 ms | 38.0 ms |
| **Workload 4: Obfuscated Hinglish Scam**| Text only | `mixed_signals` | 3 | 30.4 ms | **33.3 ms** | 28.7 ms | 40.3 ms |
| **Workload 5: Screenshot Investigation**| Image only | `insufficient_evidence` | 3 | 72.2 ms | **60.0 ms** | 58.3 ms | 74.3 ms |

*\*Note: "First Investigation" measures the initial pipeline query execution for each modality on an already-warmed process (initial branch traversal & regex caching). It must not be confused with Process Cold Start (~10.9s).*

### Latency Summary:
- Text & URL investigations achieve an average warm steady-state latency of **~30–33 milliseconds**.
- Multi-modal screenshot investigations achieve an average warm steady-state latency of **~60 milliseconds**.
- Initial investigation latency on a pre-warmed service is under **40 milliseconds** for text/URL and **72.2 milliseconds** for image OCR.

---

## 5. Memory Observations & Resource Profiling

1. **Initial Process Footprint**: 163.2 MB RSS (Python 3.13 baseline, standard library, and loaded modules).
2. **Post-Load Resident Footprint**: 549.0 MB RSS.
   - PyTorch + SentenceTransformers allocate ~371.7 MB for weights, kernel caches, and C++ shared objects.
   - Scikit-learn + NumPy references consume ~14 MB.
3. **Array Reallocation Elimination**:
   - `SemanticReferenceIndex` reuses its contiguous `float32` matrix (`(3881, 384)`) for dot-product searches.
   - Peak RSS growth during continuous batch inference of 100 queries is less than 5 MB.
4. **Image Safety Guards**:
   - Decompression bomb guard enforces `MAX_IMAGE_DIMENSION = 4096` pixels.
   - Byte size guard enforces `MAX_IMAGE_BYTES = 10 MB`.
   - Prevents memory spikes from multi-megapixel untrusted uploads.

---

## 6. Cache Behavior & Strategy

Phase 14 implemented a process-level thread-safe singleton cache (`ModelArtifactCache`) in `src/artifacts/cache.py`:

| Cached Resource | Cache Key Pattern | Lifetime | Invalidation Mechanism | Rationale |
| :--- | :--- | :--- | :--- | :--- |
| **SentenceTransformer** | `embedder:all-MiniLM-L6-v2:cpu` | Process lifetime | `clear_model_cache()` | Eliminates 10.8s reload penalty |
| **Semantic Reference Index** | `semantic_ref_index:<path>` | Process lifetime | `clear_model_cache()` | Avoids reading 3,881 records repeatedly |
| **Knowledge Retriever** | `knowledge_retriever:<path>` | Process lifetime | `clear_model_cache()` | Avoids re-chunking and fitting TF-IDF |
| **Baseline Classifier** | `baseline_classifier:<path>:0.30` | Process lifetime | `clear_model_cache()` | Eliminates repeated joblib deserialization |
| **Phase 13 Char Classifier** | `char_ngram_classifier:<path>:0.55` | Process lifetime | `clear_model_cache()` | Eliminates repeated joblib deserialization |

**Explicit Privacy Invariant**: Individual user submissions, case IDs, raw text, and investigation reports are **NEVER cached globally**. Every investigation executes fresh inference across the forensic stages, preserving user privacy and preventing stale forensic determinations.

---

## 7. Optimizations Implemented vs. Rejected

### Implemented:
1. **Thread-Safe Process Singleton Model Cache**: Reuses loaded PyTorch and Scikit-learn model instances across requests, reducing per-investigation time from ~11s (cold) to ~30ms (warm).
2. **Defensive Stage Isolation**: In `CaseAssessmentPipeline.analyze`, URL scanning, tactic detection, and classifiers are isolated in defensive try/except blocks so that an unexpected component failure produces a partial audit trail rather than crashing.
3. **Duck-Typing Classifier Interface**: Seamlessly supports both `BaselineTextClassifier` (dict output) and `CharNgramClassifier` (Phase 13 dataclass output) without schema disruption.
4. **Input Boundary Guards**: Rejects or caps inputs exceeding 50,000 characters, 2,048 URL characters, 50 URLs, or 4096x4096px images.
5. **Streamlit Session State Caching**: Prevents re-running the entire inference pipeline when users interact with UI tabs or download export buttons.
6. **Pre-Warm Facade (`service.warmup()`)**: Allows servers or CLI to eliminate the first-query latency penalty.

### Rejected and Why:
1. **Quantization of SentenceTransformer to INT8**:
   - *Reason for Rejection*: Quantizing PyTorch embeddings could slightly alter floating-point cosine similarities, potentially shifting edge-case similarity scores relative to frozen Phase 7 thresholds (`0.65`, `0.80`). Preserving exact empirical reproducibility takes precedence over minor CPU savings.
2. **Global Caching of User Query Hashes**:
   - *Reason for Rejection*: Caching investigation outputs by query text hash would violate freshness invariants (e.g. if regulatory knowledge is updated) and introduce user-data persistence risks.
3. **Asynchronous Background OCR Execution**:
   - *Reason for Rejection*: Investigation reports require synchronous multi-signal aggregation to produce an immediate deterministic verdict.

---

## 8. Reproducibility Verification

To verify absolute determinism across process executions, the benchmark ran 10 identical invocations on the complex bank phishing workload:
- **Verdict Match Rate**: 100% (`likely_scam` in all 10 runs)
- **Evidence Count Match**: 100% (10 discrete evidence items in all 10 runs)
- **Probability Stability**: Variance = `0.0000` (identical float probability)
- **Tactic Detection Set Match**: 100% (`['account_threat', 'call_to_action', 'short_timeline', 'suspicious_link', 'urgency']`)

---

## 9. Limitations

1. **Host Environment Native OCR**:
   - Native Tesseract binary is not installed on the host system. The profiler accurately reports `ocr_native_available: false` and uses `fixture_engine`. OCR timing for native Tesseract raster analysis could not be measured on this host and is not fabricated.
2. **Single-Node Execution**:
   - Benchmarks reflect single-process local CPU execution on an Intel quad-core system. Distributed scale-out characteristics were not evaluated.

---

## 10. Measurement Terminology and Runtime Reference Provenance

### 10.1 Latency Measurement Taxonomy
To prevent ambiguity when interpreting performance benchmarks, four distinct operational lifecycle stages are formally defined:

1. **Process Cold Start (~10.9 seconds total; +385.8 MB RSS)**:
   - Measured when a new Python runtime process starts from scratch without pre-existing memory state.
   - Deserializes scikit-learn models (`BaselineTextClassifier`, `CharNgramClassifier`), parses regulatory knowledge markdown, and loads the PyTorch execution engine and `all-MiniLM-L6-v2` neural weights (`10,871.2 ms`, allocating `+371.7 MB` RSS).
   - This cost is incurred **exactly once per process lifecycle** when using the Phase 14 process-level singleton cache (`ModelArtifactCache`).

2. **Warm Process (Pre-Warmed State)**:
   - The Python process has executed `service.warmup()` or completed initial artifact loading.
   - All model instances, vectorizer vocabularies, tokenizers, and the 3,881 reference embeddings reside in memory in the thread-safe singleton cache (`src/artifacts/cache.py`).

3. **First Pipeline Investigation (Cold Query on Warm Process: 26.5 ms – 72.2 ms)**:
   - The very first investigation executed for a specific input modality on an already-warmed process.
   - Models are already resident in RAM; this stage measures initial pipeline branch traversal, regex pattern compilation, and first-call lookup setup.
   - Reported as "First Investigation" in Section 4. It must **not** be confused with or compared directly to the 10.9-second process cold start.

4. **Warm Pipeline Investigation (Steady-State: 29.8 ms – 60.0 ms)**:
   - Subsequent repeated investigations across 20 iterations using the warmed pipeline.
   - Average execution times: clean text (~29.8 ms), bank phishing SMS + URL (~32.3 ms), suspicious URL (~32.0 ms), obfuscated Hinglish (~33.3 ms), and screenshot multi-modal (~60.0 ms).

### 10.2 Semantic Reference Index Provenance (3,881 Records)
- **Authoritative Reference Set**: The frozen Phase 7 semantic reference corpus contains exactly **3,881 records** (`data/semantic/reference/reference_items.jsonl`) and unit-normalized embedding matrix of shape `(3881, 384)` (`data/semantic/reference/reference_embeddings.npy`), verified by `reference_embeddings.meta.json` (`"num_samples": 3881`, `"index_size": 3881`) and SHA-256 hash `f4ad641ae6d3a34502a7f71ceaca1322762d9852c348c4e36cb767da2790101b`.
- **Dataset Partitioning**: The 3,881 records originate strictly from the stratified training partition (`train` split) of the 5,574-sample UCI SMS dataset (3,881 train, 837 validation, 856 test). Restricting the reference set to the training split was an intentional Phase 7 design decision to prevent train-test data leakage.
- **Provenance Resolution of "4,179"**:
  - The runtime index on disk has **always contained exactly 3,881 items**.
  - A physical 4,179-item index never existed. The number "4,179" was a typographical documentation error introduced in early drafts of the Phase 14 architecture narrative (conflating the sample ID label index `uci_sms_4179` with the total count).
  - The Phase 14 runtime loader (`src/artifacts/cache.py` calling `SemanticReferenceIndex.load()`) loads the authoritative 3,881-record file.
  - Frozen Phase 7 evaluation benchmarks and detection results remain completely unaltered and fully consistent with the 3,881 reference records.

