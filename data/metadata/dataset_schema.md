# ScamShield AI: Main Dataset Schema Documentation 📋

This document defines the formal schema, column definitions, data types, validation constraints, and serialization standards for the primary ScamShield AI dataset.

---

## 1. Storage & Serialization Strategy: JSONL vs. CSV

ScamShield AI utilizes a **dual-representation strategy**:

| Format | Role | Description & Rationale |
| :--- | :--- | :--- |
| **JSONL (`.jsonl`)** | **Primary Canonical Storage** | Line-delimited JSON is the native storage format. It provides **lossless, native support** for nested, structured objects such as `tactics` (arrays of strings), `urls` (arrays of strings), and `evidence_spans` (arrays of key-value dictionaries) without escaping or delimiter collision risks. |
| **CSV (`.csv`)** | **Secondary Inspection Storage** | Supported for tabular inspection, spreadsheet viewing, and quick audits. Complex structured fields (`tactics`, `evidence_spans`, `urls`) are strictly serialized as **valid JSON strings** (e.g. `'["urgency", "impersonation"]'`) rather than loose comma-separated strings. |

---

## 2. Dataset Schema Summary Table

| # | Column Name | Data Type | Required? | Nature | Allowed Values / Constraints |
| :---: | :--- | :--- | :---: | :--- | :--- |
| 1 | `sample_id` | String | Yes | System/Manual | Unique alphanumeric string (e.g., `samp_2026_000123`) |
| 2 | `text` | String | Yes | Raw content | Non-empty original message string |
| 3 | `language` | String | Yes | Derived/Manual | ISO 639-1 code (e.g., `en`, `hi`, `es`, `mul`) |
| 4 | `source_type` | String Enum | Yes | Provenance | `public_dataset`, `official_advisory`, `user_submitted`, `manually_written`, `synthetic`, `other` |
| 5 | `label` | String Enum | Yes | Manual | `scam`, `non_scam` |
| 6 | `scam_category` | String Enum | Yes | Manual | Descriptive category (14 allowed values, see below) |
| 7 | `tactics` | List[String] | Yes | Manual | Multi-label list from controlled vocabulary (23 tactics) |
| 8 | `evidence_spans` | List[Dict] | Yes | Manual | List of `{"tactic": str, "evidence": str}` items |
| 9 | `requested_action` | String Enum | Yes | Manual | Core action requested from victim (14 allowed values) |
| 10 | `target_asset` | String Enum | Yes | Manual | Primary asset targeted (13 allowed values) |
| 11 | `urgency_level` | String Enum | Yes | Manual | `none`, `low`, `medium`, `high`, `extreme` |
| 12 | `impersonated_entity`| String Enum | Yes | Manual | Entity claimed or imitated (12 allowed values) |
| 13 | `has_url` | Boolean | Yes | Derived/Manual | `true` or `false` |
| 14 | `urls` | List[String] | Yes | Derived/Manual | Extracted URLs (unvisited) |
| 15 | `has_phone_number` | Boolean | Yes | Derived/Manual | `true` or `false` |
| 16 | `has_payment_request` | Boolean | Yes | Manual | `true` or `false` (*payment request does NOT mean scam*) |
| 17 | `source_reference` | String | Yes | Provenance | Unique ID mapping to `sources.csv` or official advisory ID |
| 18 | `collection_date` | Date (String) | Yes | Provenance | ISO 8601 date: `YYYY-MM-DD` |
| 19 | `label_confidence` | String Enum | Yes | Manual | `high`, `medium`, `low` |
| 20 | `annotator_id` | String | Yes | Provenance | Identifier of annotator or pipeline (e.g., `ann_01`, `gold_panel`) |
| 21 | `pattern_group_id` | String | Yes | Grouping | Campaign/template cluster ID for **data leakage prevention** |
| 22 | `known_unknown_status`| String Enum| Yes | Curation | `known`, `held_out`, `unknown` |
| 23 | `notes` | String | No | Manual | Free-form contextual notes or edge-case observations |

---

## 3. Comprehensive Column Specifications

### 1. `sample_id`
- **Data Type**: String
- **Required**: Yes
- **Allowed Values**: Unique identifier following pattern `[a-zA-Z0-9_\-]+`
- **Meaning**: Globally unique key for every entry in the dataset.
- **Example**: `"samp_2026_001042"`
- **Rules**: Must never be duplicated within any split or across the collection.

### 2. `text`
- **Data Type**: String
- **Required**: Yes
- **Allowed Values**: Any non-empty string.
- **Meaning**: Verbatim text of the message, SMS, email, post, or communication transcript.
- **Example**: `"URGENT: Your account has been temporarily blocked. Verify your identity now at https://secure-bank.example.com or face legal action."`
- **Rules**: Preserve exact punctuation, spacing, and capitalization. Do not clean or truncate prior to ingestion.

### 3. `language`
- **Data Type**: String
- **Required**: Yes
- **Allowed Values**: ISO 639-1 language code (e.g. `en`, `hi`, `es`, `fr`) or `mul` for code-mixed / multilingual text.
- **Meaning**: Primary language in which the communication is composed.
- **Example**: `"en"`

### 4. `source_type`
- **Data Type**: String Enum
- **Required**: Yes
- **Allowed Values**:
  - `public_dataset`: Sourced from open academic or public cybersecurity corpora.
  - `official_advisory`: Extracted directly from official government, CERT, or banking advisories.
  - `user_submitted`: Anonymized real-world submissions from end users.
  - `manually_written`: Realistically drafted by domain experts to fill edge cases.
  - `synthetic`: Programmatically generated for stress-testing or novelty evaluation.
  - `other`: Unspecified legitimate external source.
- **Meaning**: Identifies the origin channel to maintain traceability.

### 5. `label`
- **Data Type**: String Enum
- **Required**: Yes
- **Allowed Values**:
  - `scam`: Content exhibits fraudulent, deceptive, or coercive malicious intent.
  - `non_scam`: Content is legitimate communication (including promotional, service alerts, or bills).
- **Meaning**: Ground-truth binary verdict.

### 6. `scam_category`
- **Data Type**: String Enum
- **Required**: Yes
- **Allowed Values**:
  - `phishing`, `impersonation`, `employment`, `shopping`, `investment`, `payment`, `romance`, `technical_support`, `government_impersonation`, `delivery`, `account_takeover`, `other`, `unknown`, `none`
- **Meaning**: Broad descriptive category intended for cataloging.
- **Critical Policy**: `scam_category` is strictly descriptive and **must NOT be treated as the primary detection mechanism**. Detection relies on behavioral tactics. If `label == "non_scam"`, this field is set to `"none"`.

### 7. `tactics`
- **Data Type**: List of Strings (`List[str]`)
- **Required**: Yes (Empty list `[]` allowed for benign non-scam samples)
- **Controlled Vocabulary**:
  1. `impersonation`
  2. `urgency`
  3. `threat`
  4. `fear_creation`
  5. `authority_claim`
  6. `payment_request`
  7. `credential_request`
  8. `otp_request`
  9. `personal_information_request`
  10. `account_suspension`
  11. `verification_request`
  12. `reward_claim`
  13. `investment_pressure`
  14. `job_offer`
  15. `emotional_manipulation`
  16. `secrecy_request`
  17. `romance_manipulation`
  18. `technical_support_claim`
  19. `refund_claim`
  20. `delivery_problem`
  21. `qr_code_request`
  22. `remote_access_request`
  23. `link_redirection`
- **Meaning**: Multi-label collection of behavioral mechanisms utilized in the message.
- **Serialization in CSV**: JSON-encoded string, e.g. `'["urgency", "verification_request"]'`.

### 8. `evidence_spans`
- **Data Type**: List of JSON Objects (`List[Dict[str, str]]`)
- **Required**: Yes (Empty list `[]` if no tactics assigned)
- **Structure**: Each entry must contain:
  - `"tactic"`: String matching an assigned tactic from `tactics`.
  - `"evidence"`: Exact substring from `text` demonstrating the tactic.
- **Example**:
  ```json
  [
    {"tactic": "urgency", "evidence": "within 24 hours"},
    {"tactic": "account_suspension", "evidence": "account will be terminated"}
  ]
  ```
- **Serialization in CSV**: JSON-encoded string.

### 9. `requested_action`
- **Data Type**: String Enum
- **Required**: Yes
- **Allowed Values**:
  - `click_link`, `send_money`, `share_otp`, `share_password`, `share_bank_details`, `share_personal_information`, `install_application`, `call_phone_number`, `scan_qr`, `download_file`, `transfer_crypto`, `reply`, `none`, `other`
- **Meaning**: The call to action demanded from the recipient.

### 10. `target_asset`
- **Data Type**: String Enum
- **Required**: Yes
- **Allowed Values**:
  - `money`, `otp`, `password`, `bank_account`, `credit_card`, `personal_information`, `identity_document`, `crypto`, `device_access`, `social_media_account`, `email_account`, `none`, `other`
- **Meaning**: The ultimate asset the perpetrator attempts to extract or compromise.

### 11. `urgency_level`
- **Data Type**: String Enum
- **Required**: Yes
- **Allowed Values**: `none`, `low`, `medium`, `high`, `extreme`
- **Meaning**: Assessed severity of artificial time pressure.

### 12. `impersonated_entity`
- **Data Type**: String Enum
- **Required**: Yes
- **Allowed Values**:
  - `bank`, `government`, `police`, `courier`, `employer`, `customer_support`, `friend`, `family_member`, `social_media_platform`, `company`, `unknown`, `none`
- **Meaning**: The identity or organization the sender purports to represent.

### 13. `has_url`
- **Data Type**: Boolean (`true` / `false`)
- **Required**: Yes
- **Meaning**: Indicates whether one or more web hyperlinks are present in the text.

### 14. `urls`
- **Data Type**: List of Strings (`List[str]`)
- **Required**: Yes (Empty list `[]` if `has_url == false`)
- **Meaning**: Unvisited, extracted URLs found in the text.
- **Policy**: URLs must never be contacted or queried over HTTP during dataset processing.

### 15. `has_phone_number`
- **Data Type**: Boolean (`true` / `false`)
- **Required**: Yes
- **Meaning**: Indicates presence of callback phone numbers.

### 16. `has_payment_request`
- **Data Type**: Boolean (`true` / `false`)
- **Required**: Yes
- **Meaning**: Indicates whether the sender asks for a financial transaction or fee.
- **Critical Policy**: `has_payment_request == true` does **NOT** imply that the message is a scam. Legitimate invoices, billing reminders, and utility receipts have payment requests.

### 17. `source_reference`
- **Data Type**: String
- **Required**: Yes
- **Meaning**: Foreign key mapping to `source_id` in `data/metadata/sources.csv` or specific publication reference.
- **Example**: `"src_cert_in_advisory_2026_04"`

### 18. `collection_date`
- **Data Type**: Date String (Format: `YYYY-MM-DD`)
- **Required**: Yes
- **Meaning**: The date when this sample was indexed or collected.

### 19. `label_confidence`
- **Data Type**: String Enum
- **Required**: Yes
- **Allowed Values**: `high`, `medium`, `low`
- **Meaning**: Confidence of the annotator in the assigned ground-truth label.

### 20. `annotator_id`
- **Data Type**: String
- **Required**: Yes
- **Meaning**: Unique identifier representing the annotator, expert panel, or automated collection pipeline.
- **Example**: `"annotator_rk_01"`

### 21. `pattern_group_id`
- **Data Type**: String
- **Required**: Yes
- **Meaning**: Identifies the underlying campaign or template family.
- **Critical Purpose**: **Data leakage prevention.** Messages sharing identical phrasing or originating from the same template must share the same `pattern_group_id` so that train/test splits group them together.
- **Example**: `"grp_fedex_unpaid_customs_2026_v1"`

### 22. `known_unknown_status`
- **Data Type**: String Enum
- **Required**: Yes
- **Allowed Values**:
  - `known`: In-distribution pattern intended for model learning and standard evaluation.
  - `held_out`: Pattern intentionally reserved from training to evaluate novelty detection.
  - `unknown`: Emerging or zero-day pattern isolated for out-of-distribution benchmark testing.

### 23. `notes`
- **Data Type**: String
- **Required**: No (Optional, defaults to empty string `""`)
- **Meaning**: Free-form qualitative annotations, dialect observations, or edge-case context.

---

## 4. Dataset-Specific Normalization Assumptions & Conventions

### A. The Spam ≠ Scam Distinction
When importing external datasets that were originally curated for general email or SMS spam filtering (such as the UCI SMS Spam Collection):
- **Raw Label `ham`** ➔ mapped to **`non_scam`**
- **Raw Label `spam`** ➔ mapped to **`scam`**

> [!WARNING]
> This translation is an operational **Dataset-Specific Normalization Assumption**, not an absolute semantic equivalence.
> - **Spam** denotes unsolicited bulk messaging (including aggressive marketing, discount coupons, ringtone offers).
> - **Scam** denotes active fraud, social engineering, credential harvesting, or extortion intended to harm the recipient.
>
> While spam and scams heavily overlap in mobile messaging, they are not identical. Because of this, imported spam records are assigned `label_confidence = "medium"` and `scam_category = "unknown"`. They must be complemented with targeted, high-fidelity scam corpora and manual annotations in subsequent phases.

### B. Pattern Groups & Unknown Campaign Convention
When an external source lacks explicit threat campaign or template cluster metadata:
- During automated dataset ingestion, records without campaign clustering retain automated row trackers (`grp_uci_unassigned_{line_num}`) for splitting integrity.
- During **human annotation**, when no reliable campaign/template relationship exists, `pattern_group_id` is strictly set to **`"unknown"`**.
- **Important**: An *unknown* campaign group is fundamentally different from a *known unique* campaign group. Human annotators must never invent synthetic unique group IDs (e.g. `grp_001`, `grp_002`) merely to fill the field.

---

## 5. Why UCI SMS Spam Collection Is Not Enough ⚠️

The UCI SMS Spam Collection is a foundational historical corpus, but it is **insufficient on its own** to power a production-grade scam detection system:

1. **Aged Threat Landscape (2011–2012)**: The dataset precedes modern attack patterns such as digital arrest scams, UPI payment gateway fraud, fake KYC update apk sideloading, deepfake audio lures, and task-based Telegram job scams.
2. **Channel & Medium Mismatch**: It exclusively contains carrier SMS text messages (160 characters), whereas modern scams predominantly propagate via instant messaging platforms (WhatsApp, Telegram, Signal) and social media.
3. **No Behavioral Tactic Annotations**: The original corpus provides only binary `ham`/`spam` tags. It lacks fine-grained tactical indicators (urgency, impersonation, authority claims, credential requests) and evidence spans.
4. **Commercial Noise (Spam vs. Scam)**: A large proportion of UCI "spam" consists of commercial competitions, adult chat promos, and ringtone subscription ads rather than malicious social engineering or account takeover campaigns.
5. **Lack of Indian / Regional Nuances**: It is purely English-centric (UK and Singapore university student traffic), lacking Indian context, regional slang, official authority names (e.g., CBI, ED, Mumbai Police, TRAI, SBI), or Hinglish code-switching.
6. **No Campaign / Template Tracking**: It lacks template grouping metadata, making realistic campaign-level leakage evaluation impossible without external clustering.

---

## 6. Indian Knowledge Source Layer & Human Annotation Pilot 🇮🇳

### A. The Indian Knowledge Source Layer
ScamShield AI distinguishes between **training data** and **knowledge/reference sources**:
- Official regulatory and law enforcement portals (**I4C / National Cyber Crime Reporting Portal**, **CERT-In**, **RBI**, **TRAI**) are designated as **`official_knowledge`**, **`official_advisory`**, or **`evaluation_reference`** sources.
- They are **NOT** training data. ScamShield does not scrape or convert government advisories into automatic training samples without verified licensing.
- Their role is to provide ground-truth definitions for the *Indian Scam Taxonomy*, supply mitigation playbooks, and inform future RAG retrieval.

### B. Distinction: Source Labels vs. Human Expert Labels
- **Source Labels**: Ingested automatically from public corpora. Binary only (`ham`/`spam`), unverified for modern scam behavior, zero tactical annotations (`tactics: []`, `evidence_spans: []`).
- **Human Expert Labels**: Produced through the structured manual review workflow (`SOURCE ➔ RAW MESSAGE ➔ ANNOTATOR ➔ VERDICT ➔ TACTICS ➔ EVIDENCE SPANS ➔ ACTIONS ➔ ASSETS ➔ URGENCY ➔ IMPERSONATED ENTITY ➔ CONFIDENCE ➔ SECOND REVIEW ➔ FINAL`). Every tactic is anchored to verbatim substring evidence.

### C. Rigorous Ambiguity Handling
When message evidence is genuinely insufficient to determine legitimacy:
- Annotators set `label_confidence = "low"`.
- Annotators set `known_unknown_status = "unknown"`.
- Annotators document the exact contextual deficit in `notes`.
- Binary verdicts are never forced on unevidenced text.

