# ScamShield AI — Phase 18B Production UI Design Specification

## 1. Product Identity & Design Principles

- **Product Name**: **ScamShield AI**
- **Tagline**: *AI-Powered Scam Investigation & Risk Analysis*
- **Core Positioning**: A multi-signal forensic investigation workbench rather than an opaque binary classifier.
- **Design Philosophy**:
  - **Calibrated Uncertainty**: Uses evidence-backed, calibrated labels (`Likely Scam`, `Likely Non-Scam`, `Mixed Signals`, `Insufficient Evidence`).
  - **Zero Overclaiming**: Avoids hyperbolic statements like "100% protection" or "guaranteed safe".
  - **Evidence Grounding**: Prioritizes "Why did the system say this?" via quoted spans and verified knowledge citations.
  - **Subordinate GenAI**: AI explanations are visually and functionally subordinate to deterministic detection verdicts.
  - **Transparent Security**: Clearly identifies passive URL analysis and offline zero-network privacy.

---

## 2. Visual Hierarchy & Design System

### 2.1 Color Palette & Semantic Mapping
| Semantic State | Hex Code | Visual Indicator | Application |
|---|---|---|---|
| **Likely Scam / High Risk** | `#DC2626` (Red-600) | 🚨 `LIKELY SCAM` | High-confidence scam indicators, severe coercion, verified threats |
| **Mixed Signals / Uncertain** | `#D97706` (Amber-600) | ⚠️ `MIXED SIGNALS` | Inconsistent signals (e.g. low model score with severe tactics) |
| **Likely Non-Scam / Low Risk** | `#16A34A` (Green-600) | ✅ `LIKELY NON-SCAM` | Clean messages, legitimate delivery OTPs, institutional domains |
| **Insufficient Evidence** | `#4B5563` (Gray-600) | ℹ️ `INSUFFICIENT EVIDENCE` | Empty content, unextractable media, low signal density |
| **Emerging / Novel Pattern** | `#7C3AED` (Violet-600) | 🔍 `POTENTIALLY EMERGING` | Low similarity to reference corpus with co-occurring tactics |

### 2.2 Typography & Spacing
- Primary font: System default sans-serif (Inter / Segoe UI / Roboto).
- Headers: Restrained H1–H4 typography with consistent emoji markers.
- Monospace: Applied to URLs, case IDs, raw extracted spans, and hashes.

---

## 3. Workflow Specifications

### 3.1 Mode 1: Quick Scan
- **Target Audience**: Everyday users seeking rapid verification of a suspicious message or link.
- **Layout**:
  - Clean text/URL input box with clear placeholder examples.
  - Prominent "⚡ Quick Scan" action button.
  - **Final Assessment Card**: High-contrast status banner, concise explanation narrative, and bulleted risk signals.
  - **Recommended Action Card**: Immediate, actionable guidance (e.g., "Do not share OTPs", "Verify through official bank app").

### 3.2 Mode 2: Deep Investigation
- **Target Audience**: Forensic analysts, security teams, and technical evaluators.
- **Layout**:
  - Multi-input ingestion (message text and/or suspect URL).
  - Configurable RAG citation depth (top-k) and explanation provider in sidebar.
  - **Structured 11-Step Investigation Output**:
    1. **Final Assessment Card**: Status, risk level, consistency, evidence level, and latency badge.
    2. **Risk Signals Matrix**: Key signals identified across classifiers, heuristics, and anomaly scores.
    3. **Scam Tactics Badges & Spans**: Expandable cards for each detected tactic with severity and quoted text matches.
    4. **Grounded Evidence Panel**: Verbatim text spans and matched entity tokens explaining detection rationale.
    5. **Passive URL Analysis**: Hostname, TLD, subdomain depth, entropy, and explicit "PASSIVE ANALYSIS ONLY" banner.
    6. **Semantic Memory & Reference Similarity**: Top-k closest matches from the 3,881-record reference corpus.
    7. **Novelty & Emerging Threat Assessment**: Cautious categorization (Known Pattern vs. Potentially Emerging).
    8. **Authoritative Knowledge Evidence**: Retrieved regulatory chunks from the local 12-document advisory base.
    9. **Grounded AI Explanation**: Plain-language synthesis with `[CASE:...]` and `[KB:...]` citations.
    10. **Recommended Actions**: Actionable incident response guidance based on risk category.
    11. **Technical Details & Forensic Audit Trail**: JSON export, component version provenance, and decision rules.

### 3.3 Mode 3: Screenshot Investigation
- **Target Audience**: Users analyzing SMS screenshots, WhatsApp chat captures, or phishing emails.
- **Layout**:
  - Image uploader supporting PNG, JPG, JPEG, WEBP (up to 10 MB).
  - Side-by-side image preview and OCR status banner.
  - **OCR Infrastructure Status Card**:
    - If Tesseract is present: Displays raw extracted text and entity extractions.
    - If Tesseract is absent: Displays graceful status: *"Native OCR is unavailable in the current environment. The system continued using the available fallback path."*
  - Unified multi-signal investigation results matching Deep Investigation standards.

---

## 4. Session History & State Management

- Maintained entirely in memory via `st.session_state["investigation_history"]`.
- Each record stores:
  - Timestamp (ISO-8601 UTC)
  - Case ID
  - Input Type (`text_only`, `url_only`, `screenshot`, `multi_modal`)
  - Content Preview (truncated to 60 characters)
  - Verdict Status (`likely_scam`, `likely_non_scam`, `mixed_signals`, `insufficient_evidence`)
  - Latency (ms)
- Provides an interactive history table and a "🗑️ Clear History" button.
- **Privacy Guarantee**: Zero disk writes of sensitive user communications.

---

## 5. Defensive Edge & Error States

| Scenario | UI Behavior & User Feedback |
|---|---|
| **Empty Input** | Displays `st.warning("Please enter text or upload an image to begin investigation.")` without invoking backend. |
| **Input > 50,000 Chars** | Text truncated to 50,000 characters; displays non-blocking informational notice. |
| **Corrupt Image** | Displays `st.error("Uploaded file could not be decoded as a valid image.")` with zero traceback. |
| **Backend Exception** | Trapped via try/except; displays `st.error("Investigation could not be completed safely. Please try again.")` and logs incident securely. |
| **LLM Grounding Failure** | Displays fallback deterministic summary with an informational notice that GenAI was suppressed for safety. |
