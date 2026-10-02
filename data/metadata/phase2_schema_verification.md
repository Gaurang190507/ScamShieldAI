# Phase 2 Schema Verification Report

## Status
PASS WITH REPAIR

---

## Input
`data/processed/uci_sms_spam.jsonl`

---

## Output
`data/processed/preprocessed/uci_sms_spam.jsonl`

---

## Canonical Schema Verification

The canonical schema defined in `src/data/dataset_schema.py` and `data/metadata/dataset_schema.md` was verified against all 5,574 output records:

* **Fields Verified (All 23 Canonical Fields)**:
  1. `sample_id` (String, unique)
  2. `text` (String, non-empty, verbatim raw)
  3. `language` (String, ISO 639-1)
  4. `source_type` (String Enum, `public_dataset`)
  5. `label` (String Enum, `scam` / `non_scam`)
  6. `scam_category` (String Enum, `none` / `unknown`)
  7. `tactics` (List[str], controlled vocabulary)
  8. `evidence_spans` (List[Dict[str, str]])
  9. `requested_action` (String Enum, `none`)
  10. `target_asset` (String Enum, `none`)
  11. `urgency_level` (String Enum, `none`)
  12. `impersonated_entity` (String Enum, `none`)
  13. `has_url` (Boolean)
  14. `urls` (List[str], extracted unvisited URLs)
  15. `has_phone_number` (Boolean)
  16. `has_payment_request` (Boolean)
  17. `source_reference` (String, provenance ID)
  18. `collection_date` (String, ISO 8601 `YYYY-MM-DD`)
  19. `label_confidence` (String Enum, `high` / `medium`)
  20. `annotator_id` (String, `uci_corpus_import`)
  21. `pattern_group_id` (String, campaign cluster ID)
  22. `known_unknown_status` (String Enum, `known`)
  23. `notes` (String, provenance notes)
* **Fields Missing**: None (`0` missing across all 5,574 records).
* **Fields Incorrectly Typed**: None (`0` type mismatches).
* **Fields Duplicated**: None at the canonical record level. (Top-level canonical metadata remains the single authoritative source of truth. Feature-level flags in `features` provide standalone numerical/boolean inputs for ML models without conflicting with or replacing canonical fields).
* **Fields Changed**: None. All 23 canonical fields match the input canonical dataset byte-for-byte (`0` changes).

---

## Preprocessing Verification

All four derived preprocessing extensions were verified across the dataset:

* `normalized_text`: Present in 5,574/5,574 records (100% valid strings with Unicode NFKC normalization and clean horizontal whitespace).
* `analysis_text`: Present in 5,574/5,574 records (100% valid lowercase derived representations preserving tokens, URLs, punctuation, and currencies).
* `entities`: Present in 5,574/5,574 records (100% valid dictionary structure containing `urls`, `phone_numbers`, `emails`, and `currency_mentions` lists).
* `features`: Present in 5,574/5,574 records (100% valid dictionary structure containing all 25 numeric, count, ratio, structural, and indicator signals). No `NaN` or `Infinity` floats detected.

---

## Record Preservation

A programmatic comparison between `data/processed/uci_sms_spam.jsonl` and `data/processed/preprocessed/uci_sms_spam.jsonl` confirmed:

* **Input Count**: `5,574`
* **Output Count**: `5,574`
* **Missing IDs**: `0`
* **Extra IDs**: `0`
* **Duplicate IDs**: `0` (all 5,574 IDs are strictly unique)
* **Changed Raw Texts**: `0` (byte-for-byte exact match on `text` across all 5,574 records)
* **Changed Labels**: `0` (labels, categories, and confidences are 100% identical)

---

## Repairs

During verification and deep cross-record inspection, two regex edge-case issues in entity extraction were detected and repaired:

1. **`CURRENCY_PREFIX_REGEX` Word Boundary Fix**:
   - *Problem*: In `src/preprocessing/extract_entities.py`, `CURRENCY_PREFIX_REGEX` used `(?:[\$£€¥₹]|Rs\.?|INR)\s*$`. Because `Rs\.?` lacked a word boundary, words ending in `"rs"` or `"inr"` (e.g., `"offers."`, `"users."`, `"numbers."`) preceding a phone number triggered false positive currency prefix rejections, causing valid phone numbers (such as `08000839402` in sample `uci_sms_1379`) to be dropped.
   - *Fix*: Added word boundaries: `re.compile(r"(?:[\$£€¥₹]|\bRs\.?|\bINR)\s*$", re.IGNORECASE)`.
2. **`PHONE_CANDIDATE_REGEX` Glued Verbs & Slash Separation**:
   - *Problem*: Phone numbers with glued verbs (e.g. `call09050000327`, `Help08714742804`) lacked a word boundary before the leading digit, and phone numbers separated by slashes (`07946746291/07880867867`) were erroneously flagged as date components.
   - *Fix*: Allowed letter lookbehind before leading `0` and `6-9` digits, and restricted date/time component rejection to adjacent numbers of length 1–4 digits.
3. **Artifact Regeneration**:
   - Re-executed `python -m src.preprocessing` to regenerate `data/processed/preprocessed/uci_sms_spam.jsonl` with 100% clean entity extraction.

---

## Phase 3 Readiness

**The Phase 2 output is structurally READY for Phase 3.**

- All canonical schema constraints and data contracts are satisfied.
- The derived preprocessing fields (`normalized_text`, `analysis_text`, `features`, `entities`) are fully populated, deterministic, and typed.
- Ground truth `text` and `label` are preserved without modification or data loss.
- 10 dedicated schema contract tests protect this interface against regressions.
