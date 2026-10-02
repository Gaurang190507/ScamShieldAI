# ScamShield AI — Phase 9A: Screenshot Ingestion & OCR Integration Specification

## 1. Executive Summary & Objective

**Phase 9A** extends ScamShield AI from purely textual inputs to multi-modal screenshot and image ingestion:

```text
Screenshot / Image
       ↓
Local Image Validation (Pillow)
       ↓
Local OCR Text Extraction
       ↓
Conservative Text Normalization
       ↓
Deterministic Entity Extraction
       ↓
Existing ScamShield AI Pipeline (Phases 3, 4, 6, 7)
       ↓
Phase 8 Multi-Signal Risk Aggregation
       ↓
Auditable Forensic Assessment
```

Phase 9A is an **OCR ingestion and integration component**. It is **not** a computer-vision scam classifier, convolutional neural network (CNN), or vision transformer.

> **Key Architectural Principles**:
> - *"Phase 9A performs OCR-based text extraction and does not independently understand visual scam cues."*
> - *"OCR errors can propagate into downstream analysis; therefore raw OCR output is preserved and no silent semantic correction is performed."*
> - *"Phase 9A empirically validated the screenshot ingestion, deterministic fixture OCR contract, entity extraction, and downstream ScamShield pipeline integration. Native OCR recognition accuracy remains unevaluated in the current environment because the Tesseract binary is unavailable."*

### Current Evaluation Environment Notice
> **Host Environment Status**:
> The evaluation environment used for Phase 9A does not currently have the native Tesseract binary installed. Therefore, the synthetic fixture evaluation uses the deterministic `FixtureOCREngine` rather than measuring recognition accuracy from a native OCR engine.
>
> The fixture results validate deterministic OCR pipeline integration and downstream processing contracts, but they do not constitute an empirical measurement of real OCR recognition accuracy.

---

## 2. Hard Architectural & Safety Constraints

1. **Zero External OCR APIs or Multimodal LLMs**: No calls to cloud vision APIs (OpenAI Vision, Gemini Vision, Claude Vision, Google Cloud Vision, AWS Rekognition).
2. **100% Local & Offline**: All processing occurs locally via Python standard libraries and Pillow.
3. **No Retraining or Modification of Prior Phases**:
   - Phase 3 text classifier: frozen.
   - Phase 4 URL engine: frozen.
   - Phase 5 hybrid baseline: frozen research milestone.
   - Phase 6 tactic detector: frozen.
   - Phase 7 semantic engine: frozen.
   - Phase 8 risk aggregation rules: frozen.
4. **No Fabricated Evidence**:
   - OCR confidence is set to `null` if the OCR engine does not produce a reliable value.
   - Spatial coordinates are flagged as `spatial_coordinates_available = false` when pixel bounding boxes are not produced.
   - Character offsets in Phase 6 represent textual character indices in `normalized_text`, never pixel coordinates.
5. **No Silent Autocorrection**: Misspelled or homoglyphic URLs (e.g., `examp1e.com`, `paypa1.com`) are passed verbatim to downstream analysis.

---

## 3. Supported Image Formats & Validation

The pipeline supports common local image raster formats:
- `.png` (Portable Network Graphics)
- `.jpg` / `.jpeg` (Joint Photographic Experts Group)
- `.webp` (WebP)
- `.bmp` (Bitmap)
- `.tiff` / `.tif` (Tagged Image File Format)

### Image Validation Checks
Before passing any file to the OCR engine, `load_and_validate_image` in [`src/ocr/image_loader.py`](file:///c:/Users/radika/OneDrive/Desktop/ScamShieldAI/src/ocr/image_loader.py) verifies:
1. **Existence**: File exists and is a regular file (`ImageNotFoundError`).
2. **Extension**: File extension is in the supported format list (`InvalidImageFormatError`).
3. **Non-Zero Size**: File contains $> 0$ bytes (`EmptyImageError`).
4. **Header Decoding**: Pillow can decode the image raster and confirm supported formats (`CorruptImageError`).
5. **Dimension Bounds**: Dimensions satisfy $\text{width} > 0$ and $\text{height} > 0$ (`CorruptImageError`).
6. **Data Integrity**: Forced memory decoding (`img.load()`) verifies the raster is uncorrupted.

---

## 4. Local OCR Engine Architecture

The OCR module uses an extensible adapter pattern defined in [`src/ocr/ocr_engine.py`](file:///c:/Users/radika/OneDrive/Desktop/ScamShieldAI/src/ocr/ocr_engine.py):

```text
               BaseOCREngine (Abstract Contract)
              /               |                 \
   TesseractOCREngine    FixtureOCREngine    AutoOCREngine
   (pytesseract local)  (Deterministic JSON)  (Transparent Coordinator)
```

### Engine Behavior:
- **`TesseractOCREngine`**: Integrates with local Tesseract installations via `pytesseract`. If Tesseract binaries are not found on the host, it safely reports `is_available() = False`.
- **`FixtureOCREngine`**: Deterministic test fixture engine that associates test image files or raster SHA256 hashes with ground-truth transcriptions from `manifest.json`. Guarantees 100% reproducible offline testing across CI and diverse operating systems.
- **`AutoOCREngine`**: Prioritizes local Tesseract if available, falls back to `FixtureOCREngine` for test fixtures, or transparently reports `status = "engine_unavailable"`.

> **Note on Evaluation Boundary**:
> The `FixtureOCREngine` is designed strictly for contract, interface, and pipeline integration validation. Output from `FixtureOCREngine` must never be conflated with real-world optical character recognition accuracy from a native OCR engine. In environments where native Tesseract is absent, native OCR recognition accuracy is formally marked as `not_evaluated`.

---

## 5. Raw vs. Normalized Text

Forensic auditing requires full separation between verbatim OCR output and normalized text:

1. **`raw_text`**:
   - The verbatim string produced by the OCR engine.
   - Retains original line breaks, irregular spacing, and raw OCR artifacts.
   - Never modified or overwritten.
2. **`normalized_text`**:
   - Produced by [`src/ocr/text_postprocessor.py`](file:///c:/Users/radika/OneDrive/Desktop/ScamShieldAI/src/ocr/text_postprocessor.py).
   - Normalizes line endings (`\r\n` $\to$ `\n`).
   - Collapses multiple horizontal spaces and tabs into a single space.
   - Collapses excessive blank lines ($\ge 3$ newlines $\to$ $2$ newlines).
   - Strips leading and trailing outer whitespace.
   - **Preserves casing, punctuation, symbols (₹, $, @, :), URLs, phone numbers, and OTP tokens.**
   - **Zero dictionary spellchecking or semantic rewriting.**

---

## 6. OCR Failure States

The extractor distinguishes four distinct operational states:

| Status Code | Condition | Success Flag | Downstream Action |
| :--- | :--- | :--- | :--- |
| `success` | Valid image, OCR extracted text | `True` | Normalized text routed through Phases 3, 4, 6, 7, and 8 |
| `no_text_detected` | Valid image, OCR returned empty text | `True` | Routed to downstream engine with empty text $\to$ evaluated as `insufficient_evidence` under `rule_empty_content` with explicit warning |
| `invalid_image` | File missing, corrupt, or unsupported | `False` | Downstream evaluation skipped, returns clear error |
| `engine_unavailable` | No OCR binary or adapter available | `False` | Downstream evaluation skipped, reports missing local OCR dependency |

---

## 7. Downstream Pipeline Integration

Extracted normalized text seamlessly enters the existing pipeline through [`ImageCaseAssessmentPipeline`](file:///c:/Users/radika/OneDrive/Desktop/ScamShieldAI/src/ocr/extractor.py#L210-L280):

### 7.1 Entity Extraction
Reuses [`src/preprocessing/extract_entities.py`](file:///c:/Users/radika/OneDrive/Desktop/ScamShieldAI/src/preprocessing/extract_entities.py):
- **URLs**: Passive regex extraction without internet contact.
- **Phone Numbers**: Phone shortcodes and mobile numbers with URL/email masking.
- **Emails**: Email regex extraction.
- **Currency**: Monetary mentions (e.g., `₹50,000`, `₹500`, `$50`).
- **OTPs**: One-time passwords and verification code mentions.

### 7.2 Phase 3 (Text Classification)
`normalized_text` is transformed by the frozen Phase 3 TF-IDF vectorizer and classified by Logistic Regression ($\tau = 0.30$).

### 7.3 Phase 4 (Passive URL Analysis)
Extracted URLs are evaluated by [`URLScanner`](file:///c:/Users/radika/OneDrive/Desktop/ScamShieldAI/src/url_analysis/url_scanner.py) for structural anomalies (IP hosts, depth, shorteners) offline.

### 7.4 Phase 6 (Tactic Detection)
Tactic rules evaluate `normalized_text`. Grounded character-level evidence spans are anchored to `normalized_text`.
- *Coordinate Guarantee*: `spatial_coordinates_available = false` explicitly certifies that spans are textual character offsets, not image pixel bounding boxes.

### 7.5 Phase 7 (Semantic Similarity & Novelty)
`all-MiniLM-L6-v2` embeds `normalized_text` and searches the 3,881 training reference items. Novelty indicates distance from training text, never guilt.

### 7.6 Phase 8 (Risk Aggregation)
Combines all normalized signals using frozen deterministic decision rules, producing a complete `CaseAssessmentResult`.

---

## 8. Forensic Audit Trail

The final evaluation result embeds an immutable [`OCRAuditTrail`](file:///c:/Users/radika/OneDrive/Desktop/ScamShieldAI/src/ocr/schemas.py#L65-L81):
```json
{
  "source_type": "screenshot",
  "engine": "fixture_engine | tesseract",
  "success": true,
  "raw_text_preserved": true,
  "network_access": false,
  "external_service": false,
  "spatial_coordinates_available": false,
  "timestamp": "2026-10-02T14:49:56.123456+00:00"
}
```

---

## 9. Security & Privacy Considerations

- **Local Storage Only**: Screenshots are read from local disk; zero image bytes are transmitted over any network socket.
- **Passive Inspection**: URLs and emails visible in screenshots are treated strictly as passive text data and are never visited, resolved, or probed.
- **No Cloud Inference**: Guarantees compliance in privacy-sensitive enterprise, legal, and banking environments.

---

## 10. Known Limitations & Future Roadmap

### Known Limitations:
1. **OCR Noise**: Blurry, low-resolution, or heavily compressed screenshots can produce character substitutions (e.g., `O` $\leftrightarrow$ `0`, `l` $\leftrightarrow$ `1`).
2. **Complex Layouts**: Multi-column chat interfaces or nested text boxes may interleave lines out of reading order.
3. **No Visual Feature Processing**: Phase 9A reads text only. It does not inspect logos, brand colors, badge authenticity, or visual layout cues.

### Future Possibilities (Beyond Phase 9A):
- Bounding-box spatial layout grouping (associating sender headers with message bodies).
- Visual brand badge verification (detecting fake verified tickmarks or forged bank seals).
- Local OCR engine pre-processing enhancements (adaptive thresholding, deskewing).
