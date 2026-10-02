# ScamShield AI — Phase 12 Evaluation Dataset Schema

## 1. Overview
The Phase 12 evaluation dataset is strictly isolated from the historical UCI training corpus (`data/processed/uci_sms_spam.jsonl`) and the semantic reference index (`data/semantic/reference/reference_items.jsonl`). It evaluates real-world robustness, generalization across modern threat vectors, hard-negative discrimination, multilingual resilience, and perturbation robustness.

---

## 2. Universal Provenance Fields

Every sample across all Phase 12 sub-benchmarks adheres to the following JSON schema:

| Field Name | Type | Description | Allowed Values / Examples |
|---|---|---|---|
| `sample_id` | `string` | Unique evaluation identifier | e.g. `p12_mod_001`, `p12_hneg_001` |
| `text` | `string` | Message content evaluated by text models | Verbatim text string |
| `language` | `string` | Primary linguistic modality | `en`, `hi`, `hi-Latn` (Hinglish) |
| `source_type` | `string` | High-level origin category | `official_advisory`, `real_public_example`, `human_curated`, `synthetic_controlled`, `transformed_controlled` |
| `label` | `string` | Ground truth classification verdict | `scam`, `non_scam` |
| `scam_category` | `string` | Specific threat taxonomy category | `upi_fraud`, `digital_arrest`, `kyc_suspension`, `e_challan`, `electricity_bill`, `task_scam`, `delivery_fraud`, `banking_otp`, `legit_utility`, etc. |
| `tactics` | `list[string]` | Applicable Phase 6 canonical tactics | Subset of the 23 canonical Phase 6 tactics |
| `evidence_spans` | `list[dict]` | Character-level ground-truth spans | `[{"matched_text": "...", "start": 0, "end": 10, "tactic": "..."}]` |
| `pattern_group_id` | `string` | Clustering ID for leakage detection | e.g. `grp_digital_arrest_cbi` |
| `known_unknown_status` | `string` | Human annotation novelty assessment | `known_pattern`, `semantically_similar`, `novel_pattern` |
| `collection_date` | `string` | ISO Date when sample was collected | `2026-10-02` |
| `source_reference` | `string` | External citation or corpus reference | e.g. `src_p12_official_advisories` |
| `provenance_type` | `string` | Rigorous provenance attribution | `real_public_example`, `official_advisory_example`, `human_curated`, `synthetic_controlled`, `transformed_controlled` |
| `license_status` | `string` | Licensing posture | `license/reuse terms require review`, `curated_fair_use`, `controlled_evaluation_synthetic` |
| `annotator_id` | `string` | Forensic annotator or curator identifier | e.g. `curator_lead`, `expert_annotator_01` |
| `annotation_confidence` | `float` | Human annotation confidence (0.0–1.0) | `1.0` |
| `notes` | `string` | Contextual investigation notes | Explanatory context |

---

## 3. Specialized Extension Fields

### A. Hard Negatives (`hard_negatives/`)
- `hard_negative_type`: Specific benign scenario containing deceptive surface signals (`legit_bank_otp`, `legit_bill_reminder`, `legit_delivery_otp`, `legit_card_block`, `legit_govt_notice`).
- `why_it_looks_suspicious`: Deceptive features present (`contains_otp`, `contains_urgency_due_date`, `contains_portal_link`).
- `why_it_is_legitimate`: Authoritative reason why content is non-fraudulent (`official_bank_sender`, `out_of_band_advice`, `informational_only`).

### B. Obfuscation & Perturbations (`obfuscated/`)
- `original_sample_id`: Identifier of source sample prior to perturbation.
- `transformation_type`: Modality of transformation (`leetspeak`, `punctuation_spam`, `spacing_insertion`, `typo_insertion`, `symbol_substitution`).
- `transformation_parameters`: Detailed configuration dictionary (`{"substitutions": {"o": "0", "e": "3"}}`).

### C. URLs (`urls/`)
- `url`: The target URL string evaluated by passive heuristics.
- `expected_risk`: Categorical expectation (`low`, `moderate`, `high`).
- `structural_flags`: Expected heuristic triggers (`ip_based_hostname`, `plain_http_sensitive`, `suspicious_path_keywords`, `punycode_domain`, `url_shortener`).

### D. Screenshots (`screenshots/`)
- `image_path`: Relative filesystem path to candidate screenshot image.
- `ground_truth_ocr_text`: Canonical textual content rendered within image.
- `expected_visual_features`: Expected layout observations (`qr_candidate_detected`, `header_banner_detected`, `button_candidate_count`).
