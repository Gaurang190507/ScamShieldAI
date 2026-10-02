# ScamShield AI — Phase 13 Evaluation Dataset Schema

## 1. Overview
This document defines the schema contract for all Phase 13 dataset records located under `data/evaluation/phase13/`.

All files are structured as newline-delimited JSON (`.jsonl`) encoded in UTF-8.

## 2. Record Fields Specification

| Field Name | Type | Allowed Values / Format | Description |
| :--- | :--- | :--- | :--- |
| `sample_id` | String | Regex: `^p13_[a-z0-9_]+$` | Unique identifier for each sample across the entire Phase 13 corpus. |
| `text` | String | Non-empty UTF-8 string | The complete text of the message (may contain Latin, Devanagari, digits, symbols). |
| `label` | String | `"scam"`, `"non_scam"` | Ground-truth binary classification label. |
| `language` | String | `"en"`, `"hi"`, `"hi-Latn"` | Linguistic classification: English, Native Hindi (Devanagari), or Romanized Hinglish. |
| `scam_category` | String | Categorical string | Operational category (e.g. `kyc_suspension`, `electricity_bill`, `digital_arrest`, `bank_otp`, `delivery_tracking`, `flight_update`, `job_scam`, `novel_threat`). |
| `tactics` | List[String]| Subset of 23 canonical tactics | Behavioral tactics present in the message (empty list for legitimate non-scam samples). |
| `evidence_spans`| List[Dict] | List of span objects | Anchored evidence substrings: `{"matched_text": str, "start": int, "end": int, "tactic": str}`. |
| `source_reference`| String | Matching `sources.csv` | Cross-reference to official provenance entry in `sources.csv`. |
| `collection_date`| String | ISO 8601 Date (`YYYY-MM-DD`)| Date of curation or acquisition. |
| `pattern_group_id`| String | Group identifier | Unique cluster grouping. Samples sharing the same `pattern_group_id` (e.g. clean/obfuscated pairs) must strictly reside in the same split. |
| `known_unknown_status`| String | `"known_pattern"`, `"novel_pattern"` | Status relative to traditional baseline training data. |
| `provenance_type`| String | `"human_curated"`, `"synthetic"`, `"real_public_example"` | Data provenance origin. |
| `phase13_source` | String | Source descriptor string | Phase 13 specific dataset source tag. |
| `augmentation_type`| String | `"none"`, `"leetspeak"`, `"spacing"`, `"punctuation"`, `"emoji"` | Perturbation or augmentation applied. |
| `language_family`| String | `"Indo-European"`, `"Indo-Aryan"`, `"Germanic"` | Broad linguistic family. |
| `script` | String | `"Latin"`, `"Devanagari"` | Orthographic script of the text. |
| `obfuscation_type`| String | `"none"`, `"spacing"`, `"leetspeak"`, `"punctuation_injection"` | Specific obfuscation tactic employed. |

## 3. Split Isolation Invariants
- `training/train.jsonl`, `validation/val.jsonl`, and `test/test.jsonl` must have **disjoint** `pattern_group_id` sets.
- 0 exact text duplicates across splits.
- 0 normalized text duplicates across splits.
- 0 overlap with historical UCI SMS (`data/processed/uci_sms_spam.jsonl`).
- 0 overlap with Phase 7 reference items (`data/semantic/reference/reference_items.jsonl`).
- 0 overlap with Phase 12 evaluation cases (`data/evaluation/phase12/`).
