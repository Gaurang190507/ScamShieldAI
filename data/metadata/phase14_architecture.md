# ScamShield AI — Phase 14 Runtime Architecture Specification

**Specification Version**: 1.0.0 (Phase 14)  
**Status**: Authoritative Production Runtime Architecture  
**Scope**: End-to-end multi-signal forensic pipeline, configuration boundaries, caching strategy, and presentation layers.

---

## 1. High-Level Runtime Architecture

```text
                     ScamShield AI
                          │
                  Investigation API
                          │
                 Input Validation
                          │
                 Input Normalization
                          │
         ┌────────────────┼────────────────┐
         ↓                ↓                ↓
       Text             URL              Image
         │                │                │
         │                │               OCR
         │                │                │
         └────────────┬───┴────────────────┘
                      ↓
               Detection Layer
                      │
        ┌─────────────┼─────────────┐
        ↓             ↓             ↓
   Phase 13       Phase 4        Phase 6
   Classifier     URL Analysis   Tactics
        │             │             │
        └─────────────┼─────────────┘
                      ↓
               Phase 7 Semantic
                      ↓
               Phase 8 Aggregation
                      ↓
              Evidence / Audit
                      ↓
           Phase 10 Explanation
                      ↓
             Investigation Report
                      ↓
              Streamlit / CLI
```

---

## 2. Component Specifications

### 2.1 Investigation API Layer
- **Modules**: `src/app/service.py` (`InvestigationService`), `src/app/schemas.py` (`InvestigationInput`, `InvestigationReport`).
- **Function**: Unified service facade coordinating all upstream forensic components.
- **Invariants**:
  * Never crashes on malformed or boundary-exceeding user input.
  * Preserves Phase 8 deterministic verdict regardless of UI state or LLM explanation status.
  * Measures per-stage latency (`timings_ms`) and injects immutable version provenance (`version_metadata`).

### 2.2 Input Validation & Resource Boundary Guards
- **Module**: `src/security/guards.py`.
- **Enforced Boundaries**:
  * Text Length: Max 50,000 characters. Safely capped with user warning.
  * URL Length: Max 2,048 characters.
  * URL Count: Max 50 URLs per submission.
  * Image File Size: Max 10 MB.
  * Image Resolution: Max 4096 x 4096 pixels (decompression bomb protection).
  * Allowed Image Formats: `.png`, `.jpg`, `.jpeg`, `.webp`.

### 2.3 Image Ingestion & Optical Character Recognition (Phase 9A)
- **Modules**: `src/ocr/extractor.py` (`OCRTextExtractor`), `src/ocr/ocr_engine.py` (`AutoOCREngine`).
- **Behavior**:
  * Local offline OCR execution.
  * Coordinates `AutoOCREngine`, selecting local native Tesseract if installed, or falling back cleanly to `FixtureOCREngine`.
  * Extracts canonical entities (URLs, phone numbers, email addresses, monetary amounts, OTP tokens) and merges them into downstream pipeline text and URL feeds.

### 2.4 Visual Feature & Observation Extraction (Phase 9B)
- **Module**: `src/vision/visual_predictor.py` (`VisualPredictor`).
- **Behavior**:
  * Extracts deterministic pixel features (color entropy, high-contrast text regions, badge detections).
  * Generates transparent contextual evidence items categorized under `VISUAL OBSERVATION`.

### 2.5 Multi-Signal Detection Layer

1. **Text Classification (Phase 3 Baseline / Phase 13 Model B)**:
   - Primary Model: Character/subword n-gram TF-IDF + Logistic Regression (`CharNgramClassifier`, Model B) operating at frozen threshold **`0.55`**, robust against Devanagari Hindi, Romanized Hinglish, and character obfuscations.
   - Frozen Baseline: Word n-gram TF-IDF + Logistic Regression (`BaselineTextClassifier`) operating at frozen threshold **`0.30`**.
   - Interface: Duck-typed interface supporting both structured dictionary outputs and `Phase13Prediction` dataclasses.

2. **Passive URL Analysis (Phase 4)**:
   - Module: `src/url_analysis/url_scanner.py` (`URLScanner`).
   - Purely passive structural analysis: IP address hosts, risky TLDs, hex/character obfuscation, entropy.
   - **Zero network requests**, **zero DNS queries**.

3. **Behavioral Tactic Detection (Phase 6)**:
   - Module: `src/tactics/tactic_detector.py` (`TacticDetector`).
   - Evaluates 23 declarative regex rules spanning urgency, authority, account threats, verification traps, directional payment language, and suspicious links.
   - Emits grounded text spans with character offsets and severity levels.

4. **Semantic Similarity & Novelty (Phase 7)**:
   - Modules: `src/semantic/embedder.py` (`TextEmbedder`), `src/semantic/reference_index.py` (`SemanticReferenceIndex`).
   - Generates 384-dimensional dense vectors via `all-MiniLM-L6-v2`.
   - Computes top-5 nearest neighbor similarities against 3,881 frozen training reference embeddings.
   - Computes relative semantic novelty score; prevents evaluation data leakage.

### 2.6 Deterministic Risk Aggregation (Phase 8)
- **Module**: `src/aggregation/aggregator.py` (`RiskAggregator`).
- **Behavior**:
  * Strictly rule-based forensic ledger evaluation.
  * Resolves priority conflicts, corroborating evidence, and hard-negative constraints.
  * Produces immutable verdict: `likely_scam`, `likely_non_scam`, `mixed_signals`, or `insufficient_evidence`.

### 2.7 Evidence-Grounded Explanation (Phase 10)
- **Modules**: `src/explanation/generator.py` (`ExplanationGenerator`), `src/rag/retriever.py` (`KnowledgeRetriever`), `src/explanation/validator.py` (`GroundingValidator`).
- **Behavior**:
  * Retrieves relevant regulatory and technical guidance passages from `data/knowledge_base/`.
  * Generates plain-language forensic explanation using configured LLM provider (`mock`, `groq`, `gemini`).
  * Enforces strict grounding validation: citations must match observed case evidence `[CASE:ev_...]` or regulatory knowledge `[KB:...]`.
  * **Resilience Guarantee**: If the LLM provider fails, times out, or lacks credentials, the system falls back to a deterministic summary template. The Phase 8 verdict is **never** lost.

---

## 3. Configuration & Caching Architecture

```text
┌────────────────────────────────────────────────────────┐
│               src/config/runtime_config.py             │
├───────────────────────────┬────────────────────────────┤
│   FrozenModelConfig       │       RuntimeConfig        │
│   (Immutable dataclass)   │   (Configurable options)   │
│   - Phase 3 thresh: 0.30  │   - Resource limits (50k)  │
│   - Model B thresh: 0.55  │   - Cache enablement       │
│   - Model C thresh: 0.50  │   - Log level / masking    │
│   - Model D thresh: 0.50  │   - Feature flags          │
└─────────────┬─────────────┴─────────────┬──────────────┘
              │                           │
              ▼                           ▼
┌───────────────────────────┐ ┌──────────────────────────┐
│   src/artifacts/manager   │ │   src/artifacts/cache    │
│   (Integrity validation)  │ │   (Singleton cache)      │
│   - File existence & size │ │   - SentenceTransformer  │
│   - SHA-256 checksums     │ │   - SemanticReference    │
│   - Schema compatibility  │ │   - KnowledgeRetriever   │
│   - No auto-download      │ │   - Baseline / Model B   │
└───────────────────────────┘ └──────────────────────────┘
```

---

## 4. Presentation & User Interfaces

1. **Command-Line Interface (CLI)**:
   - File: `src/app/cli.py`
   - Invocation: `python src/app/cli.py --text "..." [--url "..."] [--image "..."] [--json] [--warmup] [--version]`
   - Return Codes: 0 (Success), 1 (Argument Error), 2 (Execution Failure).

2. **Streamlit Interactive Console (UI)**:
   - File: `src/app/streamlit_app.py`
   - Invocation: `streamlit run src/app/streamlit_app.py`
   - Features: Multi-modal evidence input, session-state cached reports, high-visibility verdict badges, 5 multi-signal forensic tabs, citation explorer, and one-click JSON/Markdown forensic export.
