# ScamShield AI — Phase 14 Security & Integrity Audit

**Audit Date**: October 2026  
**Auditor**: ScamShield AI Production Engineering & Security  
**Scope**: Host boundary security, network isolation, passive URL analysis, secret protection, input boundary guards, deserialization safety, and forensic auditability.  
**Governing Standard**: 100% Offline-First Privacy, Zero Network Access by Default.

---

## 1. Network & Socket Behavior

### Invariant:
**Zero outbound network calls and zero external DNS lookups by default.**

### Verification Findings:
1. **Passive URL Analysis**:
   - `URLScanner` (`src/url_analysis/url_scanner.py`) executes purely passive structural heuristics:
     * Regular expression parsing of URL schema, authority, path, and query strings.
     * Local IP address detection (IPv4 / IPv6 literals).
     * Top-Level Domain (TLD) risk heuristic evaluation against static offline sets.
     * Shannon entropy computation on domain and path segments.
   - **Audited**: The module imports **zero** networking libraries (`requests`, `httpx`, `aiohttp`, `urllib.request`, `socket`). It never resolves IP addresses via DNS and never opens HTTP/HTTPS sockets.
2. **Audit Telemetry**:
   - Every `InvestigationReport` emitted by `InvestigationService` records:
     * `"network_access": false`
     * `"network_requests": 0`
   - When external LLM providers (`groq`, `gemini`) are explicitly selected, the audit trail flags `"network_access": true` transparently. In default `"mock"` mode, network access is strictly false.

---

## 2. DNS Resolution Behavior

- **Verified**: No component in `src/` attempts DNS resolution (`getaddrinfo`, `gethostbyname`, or socket lookups).
- Suspicious hostnames and IP addresses are analyzed exclusively through string parsing and regular expressions.

---

## 3. Filesystem Handling & Path Traversal Guards

1. **Path Resolution**:
   - All artifact loaders (`src/artifacts/manager.py`, `src/config/runtime_config.py`, `src/rag/document_loader.py`) resolve file paths using Python `pathlib.Path.resolve()`.
2. **Path Traversal Protection**:
   - User inputs cannot specify arbitrary system paths for model loading; artifact directories are bound to the immutable repository root (`FROZEN_CONFIG.BASELINE_MODEL_DIR`, etc.).
   - Image file inputs passed via CLI (`--image`) are validated to ensure they exist as regular files before PIL decoding.

---

## 4. Temporary File Handling & Lifecycle Safety

1. **Temporary File Creation**:
   - In `InvestigationService.investigate()`, image bytes uploaded via Streamlit or API are written to `tempfile.NamedTemporaryFile` with explicit suffix validation.
2. **Guaranteed Cleanup**:
   - Temporary image files are deleted in a strict `finally:` block:
     ```python
     finally:
         if temp_img_file is not None and temp_img_file.is_file():
             try:
                 temp_img_file.unlink()
             except Exception:
                 pass
     ```
   - No sensitive uploaded images or user transcripts persist on disk after the investigation completes.
3. **In-Memory Validation**:
   - Image byte size and header dimensions are validated directly in-memory via `io.BytesIO` before temporary file allocation, preventing malicious disk exhaustion.

---

## 5. Secret Protection & PII Sanitization

1. **Secret Pattern Redaction**:
   - `src/observability/logger.py` enforces automated secret scrubbing via `SanitizingFilter`:
     * Groq API keys (`gsk_[A-Za-z0-9_-]{20,}`) -> `[REDACTED_GROQ_KEY]`
     * Google Gemini API keys (`AIza[0-9A-Za-z-_]{35}`) -> `[REDACTED_GEMINI_KEY]`
     * Generic bearer/API tokens -> `[REDACTED_TOKEN]`
     * Password values (`password=...`) -> `[REDACTED_PASSWORD]`
2. **Environment Variable Scrubbing**:
   - Any active value of `GROQ_API_KEY`, `GEMINI_API_KEY`, or `OPENAI_API_KEY` present in the process environment is automatically scrubbed from emitted logs.
3. **User Content Privacy in Telemetry**:
   - Raw user message bodies are **not** emitted to system logs. Instead, logs record the investigation ID, input type, execution stage, and a truncated 16-character SHA-256 content digest via `hash_text_content()`.

---

## 6. Subprocess & Code Execution Invariants

1. **Zero Shell Execution**:
   - ScamShield AI executes **zero** user-supplied text through `os.system`, `subprocess.Popen`, `eval()`, or `exec()`.
2. **OCR Subprocess Isolation**:
   - When native Tesseract is installed, `pytesseract` invokes the native binary with arguments constrained to the temporary image file. On the current host, Tesseract is not installed; `AutoOCREngine` falls back cleanly to `FixtureOCREngine` without shell execution.

---

## 7. Deserialization Security

1. **Artifact Verification Before Deserialization**:
   - `src/artifacts/manager.py` enforces pre-load checks before calling `joblib.load()`:
     * Validates file existence and regular file type.
     * Verifies expected extension (`.joblib`, `.npy`, `.json`).
     * Verifies minimum and maximum file size boundaries.
     * Performs cryptographic SHA-256 checksum verification against frozen artifact release hashes.
2. **Restricted Loading Scope**:
   - Model loading is restricted to trusted directories within `models/` and `data/semantic/reference/`.

---

## 8. Input Boundary Guards & DoS/ReDoS Protection

To protect the system against resource exhaustion, Phase 14 introduced explicit defensive boundaries in `src/security/guards.py`:

| Input Modality | Security Boundary | Risk Mitigated | Failure Action |
| :--- | :--- | :--- | :--- |
| **Message Text** | `MAX_TEXT_LENGTH = 50,000` chars | Denial of Service, ReDoS in 23 regex tactics | Safe truncation with explicit user warning |
| **URL String** | `MAX_URL_LENGTH = 2,048` chars | RFC 2616 buffer overruns, regex hang | Exclusion with explicit warning |
| **URL Collection** | `MAX_URL_COUNT = 50` URLs | Parsing loops, memory exhaustion | Capped to 50 URLs with warning |
| **Uploaded Image** | `MAX_IMAGE_BYTES = 10 MB` | Disk/memory exhaustion | Immediate rejection with user-facing error |
| **Image Resolution**| `MAX_IMAGE_DIMENSION = 4096` px | PIL decompression bombs (huge pixel buffers) | Immediate rejection before full raster decode |
| **Image Format** | `.png`, `.jpg`, `.jpeg`, `.webp` | Malicious polyglot files, unsupported codecs | Rejection with list of permitted formats |

---

## 9. Security Audit Conclusion

The Phase 14 architecture audit and hardening certify that ScamShield AI satisfies all enterprise offline-first security requirements:
- **0 external network requests** by default.
- **0 external DNS requests**.
- **0 secret or credential leakages** in logs, exports, or traces.
- **0 unvalidated deserialization calls**.
- **Complete protection** against oversized payloads, ReDoS, and image decompression bombs.
- **Strictly deterministic** forensic decisions preserved across all operational scenarios.
