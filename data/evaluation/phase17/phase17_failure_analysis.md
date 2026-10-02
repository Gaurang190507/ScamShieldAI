# ScamShield AI — Phase 17 Failure Analysis & Remaining Limitations

## 1. Executive Overview

Phase 17 successfully resolved six structural engineering and routing failure modes exposed during the Phase 16 real-world audit. However, because Phase 17 strictly enforces the **Frozen Artifact Rule** (no model retraining, no threshold modification, no external network dependencies), fundamental machine-learning boundaries remain.

This document transparently details the repaired failure modes, their verified resolution mechanisms, and the residual limitations that must be addressed in subsequent deployment phases.

---

## 2. Repaired Failure Modes (FM-01 through FM-06)

| ID | Failure Mode | Phase 16 Root Cause | Phase 17 Engineering Fix | Verification Status |
|---|---|---|---|---|
| **FM-01** | Low detection on emerging / novel storylines | Rigid reliance on lexical model score defaulting low-scoring threats to `likely_non_scam` | `EmergingPatternAnalyzer` correlates semantic distance with tactical congruence | RESOLVED (elevated to `mixed_signals` / `likely_scam`) |
| **FM-02** | Poor tactic recall on conversational threats | Strict keyword matching missed conversational extortion & legal threats | `ContextualTacticEnhancer` captures multi-token authority & urgency patterns | RESOLVED (Tactic F1 improved from 0.1024 to 0.1270) |
| **FM-03** | False positive on institutional URLs (`onlinesbi`, `incometax`) | Text classifier tokenized bare URLs as scam vocabulary prose | Modality-aware `_evaluate_url_only` routing using passive structural traits | RESOLVED (URL accuracy improved 50% -> 60%, 0 false alarms) |
| **FM-04** | Misleading errors / crashes when native OCR is missing | Host machines lacked Tesseract binary, logging misleading engine errors | `OCREnvironmentDetector` checks PATH / `TESSERACT_CMD` and reports `insufficient_evidence` safely | RESOLVED (0 crashes, clean diagnostic telemetry) |
| **FM-05** | Obfuscation bypass via character spacing | Whitespace between letters (`U R G E N T`) broke n-gram tokenization | `ObfuscationNormalizer` collapses intra-word character spacing & homoglyphs | RESOLVED (Obfuscated recall improved 37.5% -> 50.0%) |
| **FM-06** | False alarm on routine delivery notifications | Delivery notifications with brand & OTP flagged as brand impersonation | Contextual brand disambiguation reclassifies doorstep handovers to `brand_mention` | RESOLVED (Hard-negative FPR reduced from 6.67% to 0.00%) |

---

## 3. Remaining Known Limitations & Architectural Boundaries

### 3.1 Non-Latin Multilingual Coverage (Devanagari Hindi)
- **Observed Behavior**: Devanagari Hindi text messages without English transliteration yield zero lexical matches against the Phase 3 TF-IDF vocabulary.
- **Root Cause**: The Phase 3 baseline model was trained exclusively on the Latin-script UCI SMS corpus.
- **Why Not Repaired in Phase 17**: Retraining the lexical classifier or replacing it with an mBERT/XLM-RoBERTa model is strictly prohibited by the Phase 1–15 frozen artifact constraint.
- **Deployment Recommendation**: In production, deploy a dedicated front-end translation/multilingual transformer pipeline ahead of the rule aggregator.

### 3.2 Pure Screenshot Ingestion Without Native OCR Binary
- **Observed Behavior**: In environments lacking the native `tesseract` binary, image-only submissions result in `insufficient_evidence` with `rule_empty_content`.
- **Root Cause**: ScamShield AI is an offline Python application and does not bundle a compiled 50MB C++ Tesseract binary distribution for every OS.
- **Why Not Repaired in Phase 17**: Bundling platform-specific native binaries or making external cloud OCR API calls violates the offline-only zero-network constraint.
- **Deployment Recommendation**: Ensure container deployment images (`Dockerfile`) include `tesseract-ocr` and language pack packages (`tesseract-ocr-eng`, `tesseract-ocr-hin`).

### 3.3 Zero-Shot Novelty Without Overt Tactical Signals
- **Observed Behavior**: Scam messages that utilize gentle, patient conversational rapport (e.g., initial stages of romance scams or task-based job scams) without urgency, legal threats, or immediate payment demands remain classified as `likely_non_scam`.
- **Root Cause**: Without lexical overlap or detectable behavioral pressure, static single-message analysis cannot distinguish friendly outreach from malicious intent.
- **Mitigation**: Multi-turn conversation history tracking is required to detect progressive grooming patterns over time.

### 3.4 Obfuscated Shortened URLs (e.g., `bit.ly`, `tinyurl.com`)
- **Observed Behavior**: Shortened URLs without suspicious keywords or IP hostnames evaluate as low structural risk.
- **Root Cause**: Resolving URL redirects requires issuing HTTP `HEAD` or `GET` requests to follow 301/302 redirects, which violates the strict zero-network requirement.
- **Deployment Recommendation**: In an online production environment, a secure sandboxed egress proxy should expand HTTP redirects before structural analysis.
