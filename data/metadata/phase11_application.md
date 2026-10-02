# ScamShield AI — Phase 11: Case Investigation Application

## 1. Overview & Objective

Phase 11 implements the first complete user-facing investigation application for ScamShield AI. It bridges the frozen deterministic detection systems (Phases 1–9B) and the evidence-grounded GenAI explanation layer (Phase 10) into a unified, transparent case investigation console.

### Core Architectural Principle
> **The UI and application services are strictly a presentation and orchestration layer.**
> **They do NOT duplicate detection logic, alter risk scores, or introduce new heuristics or rules.**

```text
User Input (Text / URL / Image)
            │
            ▼
    InvestigationInput Validation & Input Type Detection
            │
            ├─────────────────────────────────────────┐
            │ (if image uploaded)                     │ (if text or URL)
            ▼                                         ▼
   Phase 9A: Local OCR Extraction           Phase 4: Passive URL Analysis
   Phase 9B: Visual Layout Observations              │
            │                                         │
            └────────────────────┬────────────────────┘
                                 │
                                 ▼
                     Phase 8: Multi-Signal Case Aggregator
                     (Text Classifier + Tactics + Heuristics + Novelty)
                                 │
                                 ▼
                     Phase 8 Deterministic Case Assessment
                     (Status, Evidence Level, Signal Consistency)
                                 │
                                 ▼
                     Phase 10: RAG + Grounded Explanation Generator
                     (Authoritative Knowledge Retrieval + Citations)
                                 │
                                 ▼
                     Unified InvestigationReport & Presentation
                     (Streamlit UI / CLI / Markdown / JSON)
```

---

## 2. Supported Inputs & Ingestion Combinations

The application supports all permutation combinations of text, link, and screenshot inputs:

| Input Combination | Ingestion Flow | Primary Modules Executed |
|---|---|---|
| **Text Only** | Raw text ingested directly | Phases 3, 6, 7, 8, 10 |
| **URL Only** | URL ingested without text | Phase 4 (passive heuristics), Phases 8, 10 |
| **Image Only** | Screenshot loaded in memory | Phase 9A (OCR), Phase 9B (visual features), Phases 3, 6, 7, 8, 10 |
| **Text + URL** | Message text with separate link | Phases 3, 4, 6, 7, 8, 10 |
| **Text + Image** | Message text + screenshot | Phases 9A, 9B, 3, 6, 7, 8, 10 |
| **URL + Image** | Suspicious link + screenshot | Phases 4, 9A, 9B, 3, 6, 7, 8, 10 |
| **Combined All** | Text + URL + Screenshot | All modules coordinated end-to-end |
| **Empty Input** | Empty/blank submission | Safe fallback: `insufficient_evidence` (zero exceptions) |

---

## 3. UI Workflow & Layout (`src/app/streamlit_app.py`)

The Streamlit web interface is partitioned into 4 distinct functional panels:

### Panel 1: Case Evidence Ingestion & Preview
- Multi-input area: text box, link field, and image uploader.
- Instant visual preview for uploaded screenshots.
- Sidebar controls for provider selection (`mock`, `groq`, `gemini`) and citation count (`top_k`).

### Panel 2: Deterministic Case Assessment
- High-visibility status badge displaying the exact Phase 8 status:
  - 🚨 **`LIKELY_SCAM`** (Red)
  - ✅ **`LIKELY_NON_SCAM`** (Green)
  - ⚠️ **`MIXED_SIGNALS`** (Orange: "The available evidence is inconsistent or incomplete.")
  - ℹ️ **`INSUFFICIENT_EVIDENCE`** (Gray)
- Metric cards: Evidence Level (`HIGH`, `MODERATE`, `LOW`), Signal Consistency, Input Type, Case ID.

### Panel 3: Multi-Signal Forensic Evidence Panel
Organized into 5 dedicated source tabs:
- **Behavioral Tactics (Phase 6)**: Detected tactic names, verbatim matched text spans, severity, and forensic reasons.
- **Text Classifier (Phase 3)**: Logistic regression probability score, decision threshold (0.30), and classification label.
- **URL Structural (Phase 4)**: Passive heuristic findings (e.g., IP-based hostnames, path keywords, brand spoofing, entropy).
- **Semantic Memory (Phase 7)**: Cosine similarity to nearest training cluster, novelty score, and pattern status.
- **Visual & OCR (Phase 9A/9B)**: Normalized OCR text, extracted entities (phones, emails, currencies, OTPs), and visual layout observations (banners, buttons, QR candidates).

### Panel 4: Evidence-Grounded Explanation (Phase 10)
- **What ScamShield Observed**: Concrete case evidence bullet points with `[CASE:...]` citation tags.
- **Relevant Reference Guidance**: Authoritative regulatory advice with `[KB:...]` tags citing source documents (e.g., RBI BE(A)WARE, CERT-In, I4C).
- **Recommended Next Steps**: Factual safety playbook actions.
- **Provider Resilience**: If an external provider is unreachable or misconfigured, the UI clearly displays:
  `Deterministic assessment: available | AI explanation: unavailable (fallback to deterministic summary)`.

### Panel 5: Forensic Audit Trail & Export
- Interactive JSON viewer displaying pipeline execution timestamps, active components, decision rules, and network counters.
- One-click downloads for Markdown (`.md`) reports and JSON (`.json`) case dumps.

---

## 4. Privacy & Offline-First Guarantees

- **Default Offline Mode**: Default provider is `mock`. Zero network sockets, zero external API requests.
- **Zero Persistent Storage**: Uploaded screenshots are processed in memory and temporary files are automatically cleaned up in `finally:` blocks. User text is never saved to database or disk.
- **Passive URL Analysis**: ScamShield **never** makes network requests, DNS queries, or HTTP visits to untrusted URLs. Phase 4 performs structural heuristic parsing only.
- **API Key Protection**: No API keys are hardcoded in repository code, configs, logs, or audit payloads. Live providers require explicit user environment variables (`GROQ_API_KEY`, `GEMINI_API_KEY`).

---

## 5. Live Provider Behavior

When an external provider is selected in the UI or CLI:
- **Groq (`llama-3.3-70b-versatile`)**: Connects to Groq API using `GROQ_API_KEY`.
- **Gemini (`gemini-1.5-flash`)**: Connects to Google Gemini API using `GEMINI_API_KEY`.
- **Security & Transparency**: The sidebar visibly flags `External LLM API will be invoked`. The audit trail increments `network_requests = 1`.
- **Fault Tolerance**: If API keys are missing, network times out, or rate limits are encountered, an exception is caught safely; the deterministic Phase 8 verdict remains 100% visible and uncompromised.

---

## 6. Verification & Test Suite (`tests/test_app_service.py`)

A comprehensive 14-test suite validates application behavior across all scenarios:
- `test_text_only_analysis_scam`: Verifies `likely_scam` verdict and tactic evidence on phishing text.
- `test_text_only_analysis_benign`: Verifies `likely_non_scam` verdict on personal benign conversation.
- `test_url_only_analysis`: Verifies passive structural analysis on suspect IP-based URL.
- `test_image_only_analysis_with_fixture`: Verifies OCR extraction and visual observations on screenshot.
- `test_image_bytes_processing_and_cleanup`: Verifies bytes handling and automatic temporary file removal.
- `test_combined_text_and_url`: Coordinates text classifier, tactic detector, and URL scanner.
- `test_combined_all_inputs`: Verifies full multimodal coordination without signal collision.
- `test_empty_input_graceful_handling`: Guarantees zero crashes on blank input; emits `insufficient_evidence`.
- `test_nonexistent_image_graceful_handling`: Verifies graceful fallback and warning generation on missing files.
- `test_provider_failure_does_not_cause_assessment_to_disappear`: Validates that LLM 503 errors preserve Phase 8 status.
- `test_deterministic_assessment_cannot_be_overridden_by_ui`: Confirms UI assessment strictly mirrors Phase 8.
- `test_mixed_signals_preservation`: Confirms that contradictory signals preserve `mixed_signals` (no binary force).
- `test_report_serialization_and_markdown`: Validates schema serialization to dictionary and markdown.
- `test_security_audit_invariants`: Certifies 0 network requests in mock mode and absence of credential leaks.

**Cumulative Project Test Count:** 297 tests passing (283 previous + 14 Phase 11).

---

## 7. CLI Usage

The investigation engine is accessible via command-line:

```bash
# Text investigation
python -m src.app.cli --text "URGENT: Your SBI bank account suspended! Update KYC at http://192.168.1.50/kyc"

# URL investigation
python -m src.app.cli --url "http://192.168.1.50/secure/bank-update.php"

# Image investigation
python -m src.app.cli --image "tests/fixtures/images/fixture_01_scam.png"

# Output raw JSON
python -m src.app.cli --text "Hello Mom" --json
```

---

## 8. Streamlit Web App Usage

Launch the web investigation console locally:

```bash
streamlit run src/app/streamlit_app.py
```
