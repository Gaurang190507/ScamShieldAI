# ScamShield AI — Phase 15 Security Architecture & Vulnerability Audit

**Audit Date**: October 2026  
**Auditor**: ScamShield AI Security & Adversarial Engineering Team  
**Governing Standard**: Phase 15 Security & Adversarial Hardening Specification  
**Status**: Empirical Forensic Audit (Codebase Verified)  

---

## 1. Executive Summary

This forensic security audit evaluates the architecture, input validation, attack surfaces, operational boundaries, and vulnerability posture of ScamShield AI as it completes Phase 14 and transitions to Phase 15.

The investigation uncovered both robust architectural defenses (such as 100% offline default execution, passive URL parsing, and deterministic conflict rules) and notable security gaps:
1. **Windows UNC Path Network Trigger Vulnerability**: Passing a Windows UNC path (e.g., `\\evil.com\share\image.png`) to `validate_image_file_path()` or `Path.resolve()` caused the OS to initiate an outbound SMB network connection and hang on timeout, violating the strict offline invariant.
2. **Delimiter Collision in Prompt Generation**: Untrusted user text containing `END USER CONTENT (UNTRUSTED DATA)` could break out of prompt delimiters and inject directives into downstream LLMs.
3. **Secret Redaction Regex Gaps**: The existing logging sanitizer omitted HTTP `Authorization: Bearer <token>` without colons, omitted OTP digit strings, and left trailing characters in 39-character Gemini API keys.
4. **Unhandled Top-Level Exception Crash Risk**: Unexpected runtime exceptions during multi-modal investigation propagated unhandled to the user, potentially exposing internal paths and stack traces.
5. **Ungrounded Output Withholding Gap**: While `GroundingValidator` detected hallucinated or decision-contradicting text, the upstream orchestration service previously recorded the warning without actively replacing the ungrounded text with the deterministic fallback summary.

This document systematically details the trust boundaries, threat models, verified controls, and remediation architecture.

---

## 2. Trust Boundaries & Data Flow

```text
  [ Untrusted User Boundary ]
         │
         │ (text, URLs, image bytes, image paths, CLI arguments)
         ▼
┌────────────────────────────────────────────────────────────────────────┐
│ 1. Ingestion & Input Sanitization Layer                                │
│    - Length boundaries (text ≤ 50,000 chars, URL ≤ 2,048 chars)        │
│    - Safe path validation (block UNC \\, directory traversal .., nulls)│
│    - Byte & dimension bounds (image ≤ 10 MB, ≤ 4096x4096 px)           │
│    - Prompt-injection pattern detection & delimiter neutralization     │
└───────────────────────────────────┬────────────────────────────────────┘
                                    │ Sanitized Data
                                    ▼
┌────────────────────────────────────────────────────────────────────────┐
│ 2. Deterministic Detection Pipeline (Trusted Internal Core)            │
│    - Phase 2: Unicode & Whitespace Normalization (NFKC, control strip) │
│    - Phase 4: Passive URL Scanner (0 network, 0 DNS, structural checks)│
│    - Phase 6: Tactic Engine (23 declarative regex rules, bounded)      │
│    - Phase 3/13: Statistical Classifiers (TF-IDF, char n-gram)         │
│    - Phase 7: Dense Semantic Search (MiniLM embeddings, BLAS dot prod) │
│    - Phase 8: Risk Aggregation (Priority rule ledger, immutable verdict│
└───────────────────────────────────┬────────────────────────────────────┘
                                    │ Deterministic Verdict & Evidence
                                    ▼
┌────────────────────────────────────────────────────────────────────────┐
│ 3. Explanation & Boundary Isolation Layer                              │
│    - Phase 10: RAG Knowledge Retrieval (TF-IDF over local chunks)       │
│    - Strict Prompt/Data Separation (Delimited & escaped user data)     │
│    - LLM Provider Adapter (Mock default; Groq/Gemini optional API)     │
│    - Grounding Validator (Audit citations & decision consistency)      │
│    - Fail-Closed Gatekeeper (Replace ungrounded output with fallback)  │
└───────────────────────────────────┬────────────────────────────────────┘
                                    │
                                    ▼
┌────────────────────────────────────────────────────────────────────────┐
│ 4. Output & Logging Layer                                              │
│    - Structured Logging (SanitizingFilter scrubs keys, tokens, OTPs)   │
│    - Forensic Audit Compilation (Network request count, hashes)        │
│    - Zero Secret Exposure in UI/CLI                                    │
└────────────────────────────────────────────────────────────────────────┘
```

---

## 3. Comprehensive Attack Surfaces Inspected

### 3.1 Trust Boundaries & User-Controlled Inputs
| Input Channel | Entry Point | User Control Level | Potential Threats | Existing Control (Verified in Code) | Status / Gap |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **Raw Message Text** | CLI `--text`, Streamlit text area, `InvestigationInput.text` | Full user control | ReDoS, DoS via length, Unicode spoofing, prompt injection, null bytes | `validate_text()` caps at 50,000 chars; `normalize_unicode()` strips control chars 0–31. | **Gap**: Null bytes (`\x00`) and prompt delimiter strings were not explicitly sanitized. |
| **URL Input** | CLI `--url`, Streamlit URL bar, `InvestigationInput.url`, URLs in text | Full user control | Malicious schemes (`javascript:`, `file:`, `data:`), SSRF, DoS via URL count | `validate_url()` caps length (2,048 chars); `validate_url_list()` caps count (50); `parse_url()` tags unusual schemes. | **Strong**: Purely offline; zero network calls or socket connections exist in `URLScanner`. |
| **Image Upload (Bytes)** | Streamlit file uploader, `InvestigationInput.image_bytes` | Full user control | Decompression bombs, memory exhaustion, malformed headers | `validate_image_bytes()` enforces 10 MB limit and 4096x4096 px bounds before decoding. | **Strong**: Pillow safely inspects headers; temp files cleaned in `finally:` block. |
| **Image Path (String)** | CLI `--image`, `InvestigationInput.image_path` | Full user control | Path traversal, arbitrary file read, Windows UNC network leak | `validate_image_file_path()` verifies file existence and extension (`.png`, `.jpg`, `.webp`). | **Critical Vulnerability**: UNC paths (`\\host\share`) triggered Windows SMB connections and hung. |
| **LLM Provider Flag** | CLI `--provider`, `InvestigationInput.provider_name` | User/operator control | Unauthorized network calls, API key exfiltration | Provider names validated; fallback to Mock when credentials missing. | **Controlled**: Network calls strictly isolated to Groq/Gemini providers when explicitly requested. |

---

### 3.2 Internal Trusted Artifacts vs. Untrusted Content
1. **Trusted Core Artifacts**:
   - Model weights (`models/baseline/`, `models/phase13/`, `models/visual/`): Loaded via `joblib.load()` only after SHA-256 integrity verification by `ArtifactManager`.
   - Semantic Reference Corpus (`data/semantic/reference/`): 3,881 frozen embeddings and item metadata verified via SHA-256 (`f4ad641a...`).
   - Knowledge Base (`data/knowledge_base/*.json`): Static regulatory passages parsed locally; immutable.
2. **Untrusted External Content**:
   - Raw user text submissions.
   - Text extracted from OCR (may contain adversarial instructions or prompt injections).
   - URLs extracted from text or OCR.
   - User-supplied filenames and image payloads.

---

### 3.3 Model & Inference Boundaries
- **TF-IDF & Logistic Regression**: Classical scikit-learn models consume normalized text. Input dimension is strictly bounded by fixed vocabulary size (Phase 3: 5,000; Model B: 10,000). Immune to neural adversarial perturbation attacks that target gradients.
- **SentenceTransformer (`all-MiniLM-L6-v2`)**: PyTorch 6-layer transformer CPU inference. Truncates input tokens at 128 / 256. Memory footprint is bounded and isolated by the process-level singleton cache (`src/artifacts/cache.py`).
- **Phase 8 Risk Aggregator**: Strictly rule-based priority ledger. Evaluates discrete boolean evidence and floating-point probabilities. Mathematical impossibility for adversarial user text to directly alter hard priority aggregation rules.

---

### 3.4 GenAI & RAG Trust Boundaries
1. **Prompt/Data Demarcation**:
   - The LLM receives user text enclosed in `BEGIN USER CONTENT` and `END USER CONTENT`.
   - **Discovered Gap**: If user text literally contains `END USER CONTENT (UNTRUSTED DATA)`, the delimiter boundary was broken.
2. **Decision Immutability**:
   - The LLM is structurally prohibited from changing the Phase 8 decision.
   - `GroundingValidator` audits output against `SCAM_CONTRADICTIONS` and `BENIGN_CONTRADICTIONS`.
   - **Discovered Gap**: If `GroundingValidator` failed, `service.py` logged the error in the audit dictionary but did not replace the hallucinated response with the deterministic fallback summary.
3. **Citation & Evidence Grounding**:
   - Every `[CASE:...]` citation must match an observed evidence ID.
   - Every `[KB:...]` citation must match a retrieved passage chunk.

---

### 3.5 File-Processing & Filesystem Boundaries
- **Temporary Image Lifecycle**:
  - Image bytes uploaded via API or Streamlit are written to a temporary file via `tempfile.NamedTemporaryFile` and deleted in `finally:` blocks.
  - Suffix is extracted using `Path(filename).suffix`, which is restricted to `ALLOWED_IMAGE_EXTENSIONS`.
- **Path Traversal Audit**:
  - File reads in `ArtifactManager` and `reference_index.py` use pre-configured constant directory paths.
  - Image paths passed to `validate_image_file_path()` resolved arbitrary disk paths. While extension checking prevented reading non-image files, it allowed resolving arbitrary paths across the filesystem and attempting network connections for UNC paths.

---

### 3.6 Network Boundaries & Operational Isolation
- **URL Scanner**: Verified 0 networking imports (`urllib.request`, `requests`, `socket`, `httpx` are completely absent). Passive regex and structural analysis only.
- **Artifact Manager**: Verified 0 auto-download logic. If an artifact is missing or corrupted, raises `ArtifactNotFoundError` or `ArtifactCorruptedError` rather than downloading replacements.
- **Downstream LLMs**:
  - `MockExplanationModel`: 100% offline, 0 network requests.
  - `GroqExplanationModel`: Calls `https://api.groq.com/openai/v1/chat/completions` via `urllib.request`.
  - `GeminiExplanationModel`: Calls `https://generativelanguage.googleapis.com/v1beta/models/...:generateContent` via `urllib.request`.
  - Both adapters are opt-in and disabled during standard testing.

---

### 3.7 Secrets, Logging, and Configuration Boundaries
- **SanitizingFilter**:
  - `logger.py` applies `SanitizingFilter` across all logging handlers.
  - **Verified Regex Audit**:
    * Groq API key: `gsk_[A-Za-z0-9_-]{20,}` -> Redacted correctly.
    * Gemini API key: `AIza[0-9A-Za-z-_]{35}` -> Left trailing character for 39-character keys.
    * Bearer token: `(?:bearer|token|apikey)\s*[:=]\s*...` -> Missed standard HTTP header `Authorization: Bearer <token>`.
    * OTP numbers: Completely absent from filter patterns.
    * Private keys: Completely absent from filter patterns.
  - Environment keys: `GROQ_API_KEY`, `GEMINI_API_KEY`, `OPENAI_API_KEY` are stripped if present in environment variables.

---

### 3.8 Resource-Exhaustion & DoS Risks
1. **Text Payload Size**: 50,000 character maximum enforced.
2. **URL Limits**: Max 2,048 characters per URL, max 50 URLs per request.
3. **Image Dimension Limits**: 4,096 x 4,096 pixels maximum (16.7 megapixels), preventing PIL decompression bombs.
4. **Image File Size**: 10 MB maximum byte length.
5. **ReDoS (Regular Expression Denial of Service)**:
   - All 23 tactic regex patterns were benchmarked on 50,000-character pathological repetitive strings (50k `'a'`, 50k `'!@#$'`, 54k URLs, 50k zero-width chars).
   - Maximum elapsed execution time across all 23 rules was **< 950 milliseconds**. Zero catastrophic backtracking discovered.

---

## 4. Existing Controls vs. Identified Gaps

| Security Domain | Existing Control (Phase 14) | Verified Posture | Identified Security Gap | Phase 15 Hardening Action |
| :--- | :--- | :--- | :--- | :--- |
| **File / Path** | Extension check (`.png`, `.jpg`, `.webp`), size check (10 MB) | Working | UNC paths (`\\host\share`) cause Windows network hang; traversal allowed | Implement `validate_safe_path()`: reject UNC paths, traversal (`..`), null bytes, Windows reserved names. |
| **Prompt Injection** | Static delimiter strings in prompt template | Working on simple text | Delimiter breakout via `END USER CONTENT`; no active injection detection | Implement `detect_prompt_injection()`; sanitize delimiter markers; tag audit trail. |
| **GenAI Grounding** | `GroundingValidator` audits citations & status | Working | Failed grounding was audited but ungrounded text was not withheld | Gatekeeper: When grounding fails, replace output with deterministic fallback summary. |
| **Secret Sanitization** | `SanitizingFilter` in `logger.py` | Partially working | Misses `Bearer <token>`, OTP digits, trailing Gemini chars | Update `SECRET_PATTERNS` to cover Bearer tokens, full Gemini keys, OTPs, private keys. |
| **Error Handling** | Defensive isolation inside pipeline stages | Working for stages | High-level `investigate()` lacked top-level try/except, risking crash | Implement top-level fail-closed handler returning safe `insufficient_evidence` report with diagnostics. |
| **URL Security** | Passive parsing; unusual schemes tagged | Working | Dangerous schemes (`javascript:`, `data:`, `file:`) not flagged in audit | Log explicit security audit events when dangerous schemes are detected. |

---

## 5. Security Invariant Matrix

The Phase 15 implementation must strictly uphold the following 10 invariants:

1. **INVARIANT 1**: No user-controlled input can cause network access.
2. **INVARIANT 2**: No URL is fetched, resolved, or downloaded by passive URL analysis.
3. **INVARIANT 3**: User-controlled paths cannot escape controlled directories or invoke network UNC shares.
4. **INVARIANT 4**: Resource limits are enforced before expensive model or image processing.
5. **INVARIANT 5**: Untrusted content cannot become trusted system instructions.
6. **INVARIANT 6**: GenAI explanations cannot override authoritative deterministic detection results.
7. **INVARIANT 7**: Secrets, tokens, and credentials are never exposed through logs, reports, or errors.
8. **INVARIANT 8**: Malformed or adversarial input produces controlled failure rather than application crash.
9. **INVARIANT 9**: Security processing failures cannot silently produce a false "safe" (`likely_non_scam`) verdict.
10. **INVARIANT 10**: Frozen Phase 1–14 artifacts and historical benchmarks remain 100% immutable.
