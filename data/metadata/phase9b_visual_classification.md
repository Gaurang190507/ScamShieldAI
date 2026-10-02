# ScamShield AI — Phase 9B: Visual Scam Classification & Forensic Evidence

## 1. Overview & Objectives

Phase 9B extends ScamShield AI to investigate whether **visual information itself** (independent of OCR text extraction) provides measurable scam-related signal.

### Core Scientific Question
> *"Does visual information provide measurable scam-related signal that is not already captured by OCR text?"*

Phase 9B is designed as a **controlled, reproducible, offline empirical experiment**. It evaluates:
1. **Visual Feature Extraction**: Deterministic pixel and layout geometry, luminance, chromatic distribution, edge density, and structural layout heuristics.
2. **Supervised Statistical Classification**: A Logistic Regression classifier trained **strictly on the training split**, with decision thresholds calibrated **strictly on the validation split**.
3. **Multimodal Experimentation**: Comparative analysis across:
   - **Experiment A**: Text-Only Baseline (Phase 3 TF-IDF + Logistic Regression).
   - **Experiment B**: Visual-Only Baseline (Phase 9B).
   - **Experiment C**: Multimodal Fusion (Text + Visual combination).
4. **Hard-Negative Sensitivity**: Rigorous assessment on benign screens with QR codes, OTP prompts, and urgent security banners.
5. **Paired Variation Experiments**:
   - *Paired Layout*: Identical visual template with scam vs. benign text.
   - *Paired Text*: Identical scam text with styled vs. plain visual layout.

---

## 2. Architectural Boundaries & Non-Negotiable Constraints

To maintain scientific integrity and system safety:
- **Zero Retraining of Prior Phases**: Phases 1–8 and Phase 9A remain 100% frozen.
- **Zero External Networks or APIs**: Completely offline, self-contained, and deterministic.
- **No Heavy Deep Learning**: No CNNs, vision transformers, multimodal LLMs, or cloud vision APIs.
- **No OCR Feature Leakage**: Visual features are extracted strictly from image pixels and spatial geometry. No OCR text lengths, word counts, or lexical tokens are fed into the visual feature vector.
- **Zero Cross-Split Leakage**: Splits are partitioned strictly by `pattern_group_id`, certified via exact SHA-256 and perceptual 64-bit dHash audits.

---

## 3. Visual Feature Set Specification

The feature extractor (`src.vision.image_features.extract_visual_features`) extracts an ordered 20-dimensional numerical feature vector:

| # | Feature Name | Type | Description |
|---|---|---|---|
| 1 | `width` | Integer | Image raster width in pixels. |
| 2 | `height` | Integer | Image raster height in pixels. |
| 3 | `aspect_ratio` | Float | Ratio of width to height (\(\frac{\text{width}}{\text{height}}\)). |
| 4 | `mean_brightness` | Float | Average grayscale pixel luminance \([0.0, 255.0]\). |
| 5 | `std_brightness` | Float | Contrast metric across all pixels. |
| 6 | `entropy` | Float | Shannon entropy of pixel intensity distribution in bits. |
| 7 | `whitespace_ratio` | Float | Fraction of near-white background pixels (\(> 240.0\)). |
| 8 | `mean_red` | Float | Mean red channel intensity \([0.0, 255.0]\). |
| 9 | `mean_green` | Float | Mean green channel intensity \([0.0, 255.0]\). |
| 10 | `mean_blue` | Float | Mean blue channel intensity \([0.0, 255.0]\). |
| 11 | `red_ratio` | Float | Proportion of red channel relative to total RGB energy. |
| 12 | `mean_saturation` | Float | Mean HSV saturation \([0.0, 1.0]\). |
| 13 | `color_variance` | Float | Variance across the mean RGB channels. |
| 14 | `edge_density` | Float | Proportion of pixels exceeding 2D Sobel spatial gradient threshold. |
| 15 | `top_luminance_ratio` | Float | Ratio of top 20% luminance to overall mean brightness. |
| 16 | `bottom_luminance_ratio` | Float | Ratio of bottom 20% luminance to overall mean brightness. |
| 17 | `horizontal_asymmetry` | Float | Absolute difference in luminance between left and right halves. |
| 18 | `header_banner_detected` | Boolean | Binary flag indicating distinct contrasting top header strip. |
| 19 | `button_candidate_count` | Integer | Count of rectangular contrasting action button bands in lower region. |
| 20 | `qr_candidate_detected` | Boolean | Binary flag indicating high-variance, square-like 2D matrix pattern. |

---

## 4. Controlled Dataset Design

The evaluation corpus (`data/visual/`) contains 28 controlled synthetic visual samples across 14 distinct layout archetypes:

### Group A: Legitimate Communications (\(N=8\))
- `group_a_delivery`: E-commerce delivery tracking with stepper nodes.
- `group_a_statement`: Formal monthly banking e-statement with multi-row table.
- `group_a_promo`: Retail sale announcement flyer with discount splash badge.
- `group_a_chat`: Personal chat messenger interface with conversational bubbles.

### Group B: Scam Communications (\(N=8\))
- `group_b_account_lock`: Urgent account suspension modal on dimmed background.
- `group_b_lottery`: Celebratory lottery scratch voucher with prize claim seal.
- `group_b_kyc`: Urgent KYC renewal phish with credential input boxes.
- `group_b_qr_phish`: Malicious QR payment screen promising incoming refund.

### Group C: Hard Negatives (\(N=8\))
Benign communications engineered with layout patterns commonly stereotyped as fraudulent:
- `group_c_legit_qr`: Legitimate retail POS grocery receipt with dynamic QR code.
- `group_c_legit_otp`: Legitimate 3D Secure bank OTP entry keypad with security warnings.
- `group_c_legit_urgent_alert`: Authentic bank security alert regarding unauthorized login.
- `group_c_legit_card_payment`: Credit card billing summary card with chip graphic.

### Paired Variations (\(N=4\))
- `group_paired_layout`: Identical red alert layout template paired with scam text (`paired_layout_scam`) vs. benign text (`paired_layout_legit`).
- `group_paired_text`: Identical urgent scam text presented in styled alert graphic (`paired_text_styled`) vs. plain unformatted monochrome note (`paired_text_plain`).

---

## 5. Leakage Prevention & Audit

Dataset splitting enforces strict group isolation via `src.vision.leakage.partition_by_group`:
- **Training Split**: 16 records across 8 pattern groups.
- **Validation Split**: 4 records across 2 pattern groups.
- **Test Split**: 8 records across 4 pattern groups.

The audit utility (`src.vision.leakage.audit_visual_leakage`) verifies:
1. `exact_duplicate_overlap`: **0**
2. `perceptual_duplicate_overlap` (Hamming distance \(\le 2\)): **0**
3. `pattern_group_overlap`: **0**
4. **Certification**: **`is_leakage_free: True`** (documented in `data/visual/metadata/leakage_report.json`).

---

## 6. Key Empirical Conclusions

1. **Visual Features Are Corroborating Signals, Not Autonomous Verdicts**:
   - The visual-only model achieved high recall on visually styled scam alerts but suffered from elevated false positives on hard negatives (e.g., legitimate QR receipts and bank security warnings).
   - In paired layout tests where the visual layout is identical, the visual classifier outputs identical probabilities, failing to detect differences in intent without lexical grounding.
2. **Text Grounding Is Indispensable**:
   - The frozen Phase 3 text model reliably separated scam from benign text across identical layout templates.
3. **Multimodal Fusion Role**:
   - Multimodal combination (e.g. 70% text + 30% visual) provides explainable visual forensic evidence while maintaining protection against visual false positives.
