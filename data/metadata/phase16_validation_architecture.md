# ScamShield AI — Phase 16 Validation Architecture & Methodology

## 1. Overview and Purpose
Phase 16 executes a comprehensive, independent, real-world end-to-end evaluation of the complete ScamShield AI system.
Unlike earlier unit evaluations or synthetic evaluations, Phase 16:
1. Evaluates the full production pipeline via the unified `InvestigationService.investigate()` entry point.
2. Uses an independently constructed validation corpus covering diverse modern threat categories, multilingual variations, obfuscations, passive URL analysis, screenshot inputs, and adversarial prompt-injection vectors.
3. Operates strictly under **zero-network constraints** (100% offline, local semantic search, local regex and rule engines, passive URL feature extraction, local RAG retrieval, and deterministic fallback validation).
4. Strictly respects the frozen boundary: **zero model retraining, zero threshold modifications, zero prompt alterations, and zero tampering with historical datasets or reports**.

---

## 2. Investigation Architecture Under Test

The complete end-to-end pipeline operates according to the following component flow:

```
                      +---------------------------------------+
                      |         InvestigationInput            |
                      |  (text, image_path, url, case_id)     |
                      +---------------------------------------+
                                          |
                                          v
                      +---------------------------------------+
                      |       Input Security & Guardrails     |
                      |  (Path Traversal Check, Size Check,   |
                      |   Injection Guard, PII Redaction)     |
                      +---------------------------------------+
                                          |
                       +------------------+------------------+
                       |                                     |
                       v                                     v
            [Text & Extracted URLs]                 [Image File Path]
                       |                                     |
                       |                                     v
                       |                         +-----------------------+
                       |                         |   Phase 9A OCR Engine |
                       |                         |   & 9B Visual Feature |
                       |                         +-----------------------+
                       |                                     |
                       +------------------+------------------+
                                          | (Extracted Text merged)
                                          v
                      +---------------------------------------+
                      |         Text Processing Pipeline      |
                      | - Phase 3 TF-IDF Classifier (t=0.30)  |
                      | - Phase 13 Char N-Gram (t=0.55)       |
                      | - Phase 4 Passive URL Analyzer        |
                      | - Phase 6 Tactic & Evidence Engine    |
                      | - Phase 7 Semantic Similarity Search  |
                      |   & Novelty Scorer (Cosine / Min-Dist)|
                      +---------------------------------------+
                                          |
                                          v
                      +---------------------------------------+
                      |      Phase 8 Risk Aggregator          |
                      |  (Multi-Signal Evidence Synthesis,    |
                      |   Deterministic Status Resolution)    |
                      +---------------------------------------+
                                          |
                                          v
                      +---------------------------------------+
                      |     Phase 10 RAG & Explanation Layer  |
                      | - Regulatory Knowledge Base Retrieval |
                      | - GenAI / Deterministic Explanation   |
                      | - Phase 15 Fail-Closed Gatekeeper     |
                      |   (Hallucination / Action / URL check)|
                      +---------------------------------------+
                                          |
                                          v
                      +---------------------------------------+
                      |       Final InvestigationResult      |
                      |  (verdict, risk_level, confidence,    |
                      |   tactics, actions, grounding, timing)|
                      +---------------------------------------+
```

---

## 3. Modality Routing and Multi-Signal Execution
Each validation test case activates the modalities relevant to its input characteristics:
- **Text-Only Cases**: Processed through Text Normalization, Baseline TF-IDF, Char N-Gram, Tactic Detection, Semantic Similarity, Novelty Detection, Phase 8 Aggregation, and RAG Explanation.
- **URL-Bearing Messages**: Concurrently extract and passively analyze URL structures (FQDN, TLD, suspicious subdomains, path entropy, IP addressing, shortener detection) without any network resolution.
- **Multilingual Messages**: Evaluated across English, Native Devanagari Hindi, Romanized Hinglish, and Mixed-Script formats to evaluate sub-word and tokenization coverage.
- **Obfuscated Cases**: Evaluated against character substitution, spacing, emoji injection, and homoglyphs.
- **Image / Screenshot Cases**: Routed through Phase 9A OCR extraction. Both raw OCR text and visual heuristic observations are fused into the pipeline.
- **Adversarial / Injection Cases**: Evaluated against the Phase 15 input security filter and RAG grounding validator to verify that user input cannot subvert investigation results.

---

## 4. Evaluation Corpus Specification

The dataset schema (`data/evaluation/phase16/phase16_dataset_manifest.jsonl`) captures 28 distinct attributes per sample:
1. `sample_id`: Unique identifier (e.g., `P16-C01-001`).
2. `case_group`: Evaluation category (C1 through C8).
3. `input_type`: `text`, `url`, `image`, or `multimodal`.
4. `text`: Message body (with all real PII redacted).
5. `image_path`: Path to mock or synthetic screenshot image fixture (or null).
6. `urls`: List of extracted URLs (or empty).
7. `language`: Language classification (`en`, `hi`, `hinglish`, `mixed`).
8. `script`: Script classification (`Latin`, `Devanagari`, `Mixed`).
9. `ground_truth_label`: Authoritative classification (`scam` or `non_scam`).
10. `scam_category_if_known`: Specific scam category if known (e.g., `bank_kyc`, `upi_fraud`, `part_time_job`, `courier_customs`, `police_threat`, etc.).
11. `known_unknown_status`: `known`, `unknown`, or `emerging`.
12. `primary_tactics`: Expected primary tactic identifiers.
13. `secondary_tactics`: Expected secondary tactic identifiers.
14. `requested_action`: Primary caller action (e.g., `click_link`, `transfer_money`, `share_otp`, `install_apk`).
15. `target_asset`: Targeted asset (`money`, `credentials`, `identity`, `none`).
16. `impersonated_entity`: Entity being impersonated (or `none`).
17. `urgency_level`: `high`, `medium`, `low`, `none`.
18. `payment_request`: Boolean flag.
19. `credential_request`: Boolean flag.
20. `otp_request`: Boolean flag.
21. `source_type`: `curated_real_world`, `adversarial_synthetic`, `legitimate_notification`.
22. `source_reference`: Documented origin or public threat advisory reference.
23. `collection_date`: Date recorded (2026-10-03).
24. `transformation`: Transformation applied (e.g., `pii_redacted`, `character_obfuscation`, `devanagari_transliteration`, `none`).
25. `provenance`: Detailed origin metadata.
26. `human_review_status`: `verified_independent_double_review`.
27. `label_confidence`: `high` (1.0).
28. `review_notes`: Adjudication and contextual notes.

---

## 5. Metric Computation Formulations

### 5.1 Binary Classification (Scam Detection)
- **Accuracy**: $(TP + TN) / (TP + TN + FP + FN)$
- **Scam Precision**: $TP / (TP + FP)$
- **Scam Recall**: $TP / (TP + FN)$
- **Scam F1**: $2 \times \frac{\text{Precision} \times \text{Recall}}{\text{Precision} + \text{Recall}}$
- **Hard-Negative False Positive Rate (FPR)**: $FP_{\text{hard\_neg}} / (FP_{\text{hard\_neg}} + TN_{\text{hard\_neg}})$
- **False Negative Rate (FNR)**: $FN / (FN + TP)$

### 5.2 Multi-Label Tactic Detection
- **Micro-averaged Precision, Recall, and F1** computed across all detected vs expected tactic labels.
- **Exact Set Match Rate**: Proportion of samples where detected tactics exactly match ground-truth tactics.

### 5.3 Semantic & Novelty Behavior
- Distribution of cosine distance / similarity against the 3,881 frozen reference cases.
- Separation margin between known scam references and emerging/unknown patterns.

### 5.4 Privacy & Ethical Safeguards
- Real phone numbers masked with `+91-XXXXX-XXXXX` or `+91 98765 00000` test ranges.
- Real account numbers, UPI IDs, OTP codes, and personal citizen names systematically redacted prior to storage.
- All testing performed fully offline without contacting remote servers.
