# ScamShield AI — Phase 16 Failure Analysis & Root Cause Audit

## 1. Overview
This document conducts a root-cause forensic investigation of every major false positive and false negative observed during Phase 16 independent evaluation.
All failures are mapped to architectural layers and classified as either **Previously Known Limitations** (from Phases 12/13) or **Newly Discovered Limitations**.

## 2. Failure Mode Taxonomy & Breakdown

### FM-01: Native Devanagari Hindi Out-of-Vocabulary (OOV)
- **Category**: Language & Tokenization Gap
- **Historical Status**: Known limitation from Phase 12 (0.00% recall) and Phase 13.
- **Manifestation**: Samples `P16-C04-001` (Devanagari electricity cutoff) and `P16-C04-002` (Devanagari SBI KYC block).
- **Root Cause**: The Phase 3 baseline TF-IDF vectorizer was trained strictly on historical English SMS messages. Pure Devanagari Unicode sequences yield a 100% OOV rate, causing zero positive term overlap. The text classifier outputs default low scores (p < 0.15).
- **System Result**: Both samples fell back to `mixed_signals` or `likely_non_scam`. Strict recall = 0.00% (0/2).

### FM-02: Local OCR Host Dependency Failure
- **Category**: Multimodal / OCR Infrastructure Limitation
- **Historical Status**: Known architectural constraint from Phase 9A.
- **Manifestation**: All 8 screenshot test fixtures (`P16-C07-001` through `P16-C07-008`).
- **Root Cause**: The local OCR engine (`src/ocr/extractor.py`) relies on an external native Tesseract executable. When Tesseract is not installed on the host OS and the image is not a pre-cached synthetic test fixture, OCR gracefully returns empty string with a diagnostic warning.
- **System Result**: OCR text extraction rate was 0.0% (0/8). Multi-modal decisions relied entirely on heuristic visual features and URL extraction.
- **Resilience Observation**: Zero crashes occurred; the pipeline safely fell back without unhandled exceptions.

### FM-03: URL-Only Text Model Bleed (False Positives on Institutional Domains)
- **Category**: Cross-Modality Input Handling Defect
- **Historical Status**: **NEWLY DISCOVERED LIMITATION (Phase 16)**.
- **Manifestation**: `P16-C06-006` (`https://www.onlinesbi.sbi/`) and `P16-C06-007` (`https://www.incometax.gov.in/iec/foportal/`).
- **Root Cause**: When an input contains *only* a URL without an accompanying message body, `InvestigationService` passes the raw URL string as the text input to `CaseAssessmentPipeline`. The Phase 3 TF-IDF vectorizer extracts sub-word tokens (e.g. `sbi`, `http`, `www`, `gov`, `incometax`). Because keywords like `sbi` appeared disproportionately in scam training SMS, Phase 3 outputs `p = 0.5826` (well above the `0.30` threshold). Combined with the Phase 6 `impersonation` rule firing on `sbi`, Phase 8 declares `likely_scam`.
- **Impact**: Produces false positives on legitimate institutional URLs when submitted in isolation without message context.

### FM-04: Token Boundary Destruction via Character Spacing
- **Category**: Obfuscation Fragility
- **Historical Status**: Known limitation from Phase 12.
- **Manifestation**: `P16-C05-001` (`D e a r  c u s t o m e r, y o u r  b a n k...`).
- **Root Cause**: Unigram and bigram word tokenizers split spaced characters into single-letter tokens (`d`, `e`, `a`, `r`), completely bypassing keyword dictionaries and TF-IDF features.
- **System Result**: Strict recall on obfuscated group was 37.50% (3/8).

### FM-05: Emerging Threat Novelty Compression
- **Category**: Semantic Distance / Novel Storyline
- **Historical Status**: Known limitation from Phase 12/13.
- **Manifestation**: `P16-C02-001` (Digital arrest judicial custody), `P16-C02-003` (Green hydrogen syndicate), `P16-C02-007` (Corporate PF exit audit).
- **Root Cause**: The 3,881 frozen semantic reference embeddings are centered on traditional lottery, banking, and prize themes. Novel storylines have high cosine distance (>0.55), but without explicit keyword matches or high TF-IDF scores, Phase 8 defaults to `mixed_signals` rather than `likely_scam`.
- **System Result**: Strict recall on unknown/emerging threats was 10.00% (1/10). However, 60.00% (6/10) were flagged as `mixed_signals`.

### FM-06: Hard Negative Delivery Code Impersonation
- **Category**: Heuristic Tactic Over-Triggering
- **Historical Status**: Rare edge-case false positive.
- **Manifestation**: `P16-C03-003` (`Your Amazon delivery agent is out for delivery. Share delivery code 491024...`).
- **Root Cause**: Brand mention `Amazon` combined with delivery agent and verification code triggered Phase 6 `impersonation` tactic, elevating risk to `likely_scam`.
- **System Result**: 1 out of 15 hard negatives was falsely flagged (6.67% FPR).

## 3. Comprehensive Discrepancy Registry
| Sample ID | Case Group | Ground Truth | System Status | Failure Mode | Component Involved | Limitation Type |
|---|---|---|---|---|---|---|
| `P16-C04-001` | C4_multilingual | scam | `mixed_signals` | FM-01 (Devanagari OOV) | Phase 3 TF-IDF | Previously Known (P12/P13) |
| `P16-C04-002` | C4_multilingual | scam | `mixed_signals` | FM-01 (Devanagari OOV) | Phase 3 TF-IDF | Previously Known (P12/P13) |
| `P16-C05-001` | C5_obfuscated | scam | `mixed_signals` | FM-04 (Token Spacing) | Phase 2 Preprocessing | Previously Known (P12) |
| `P16-C06-006` | C6_url_cases | non_scam | `likely_scam` | FM-03 (URL Text Bleed) | Pipeline / Aggregation | **Newly Discovered (P16)** |
| `P16-C06-007` | C6_url_cases | non_scam | `likely_scam` | FM-03 (URL Text Bleed) | Pipeline / Aggregation | **Newly Discovered (P16)** |
| `P16-C03-003` | C3_hard_negatives | non_scam | `likely_scam` | FM-06 (Brand Heuristic) | Phase 6 Tactic Detector | Previously Known (P12) |
| `P16-C07-001` | C7_screenshot | scam | `mixed_signals` | FM-02 (Host OCR Missing) | Phase 9A OCR | Previously Known (P9A) |
| `P16-C02-001` | C2_unknown | scam | `mixed_signals` | FM-05 (Novel Storyline) | Phase 8 Aggregator | Previously Known (P12/P13) |
