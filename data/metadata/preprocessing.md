# Preprocessing & Deterministic Feature Extraction Specification

**ScamShield AI — Phase 2 Architecture Documentation**

---

## 1. Why Preprocessing Exists

In adversarial scam detection, raw inbound text from SMS, WhatsApp, messaging apps, and emails exhibits significant stylistic variance, obfuscation techniques, and informal linguistic traits. 

The deterministic preprocessing layer serves three foundational functions:
1. **Structural Normalization**: Cleans standard formatting inconsistencies (whitespace irregularities, encoding artifacts, CRLF differences) without destroying critical signal context.
2. **Deterministic Feature Extraction**: Quantifies empirical, observable attributes (length statistics, casing distribution, punctuation streaks, currency indicators, presence of unvisited contact channels) into structured numerical and boolean vectors suitable for classical ML, rules engines, and novelty detection.
3. **Safe Entity Extraction**: Isolates actionable textual components (URLs, emails, phone numbers, monetary values) strictly as passive text data without making external network queries.

> **CRITICAL PRODUCT PRINCIPLE:**
> **These features are signals, not scam labels.**
> 
> Preprocessing answers only: *"What observable properties does this message contain?"*
> It NEVER determines: *"Is this message a scam?"*

---

## 2. Three-Tier Text Representations

To reconcile the conflicting demands of auditability, strict evidence preservation, and statistical NLP modeling, ScamShield AI maintains three distinct text representations:

| Representation | Field Name | Description | Downstream Use Cases |
| :--- | :--- | :--- | :--- |
| **Raw Original Text** | `text` | The unaltered, byte-for-byte original string from the source dataset. | Evidence citation, human auditing, forensic logging, future generative explanations. |
| **Normalized Text** | `normalized_text` | Conservatively cleaned text applying Unicode NFKC normalization, stripped non-printable control characters, and standardized whitespace. Casing, punctuation, URLs, emojis, and words are 100% preserved. | Entity extraction, human UI presentation, token-level span alignment. |
| **Analysis Text** | `analysis_text` | Lowercased derived representation derived from normalized text. Retains all punctuation, URLs, numbers, emojis, and stopwords. | TF-IDF vectorization, n-gram extraction, vocabulary matching in classical ML. |

---

## 3. Deterministic Features Catalog

All features extracted in Phase 2 are implemented in `src/preprocessing/extract_features.py` and structured via `TextFeatures`:

### Numerical & Length Statistics
- `character_count`: Total character length (\(N_{chars}\)).
- `word_count`: Total whitespace-delimited tokens.
- `digit_count`: Count of numeric digits `[0-9]`.
- `uppercase_count`: Count of uppercase alphabetical characters `[A-Z]`.
- `uppercase_ratio`: Proportion of uppercase characters: \(\frac{\text{uppercase\_count}}{\max(\text{character\_count}, 1)}\).
- `digit_ratio`: Proportion of digit characters: \(\frac{\text{digit\_count}}{\max(\text{character\_count}, 1)}\).
- `exclamation_count`: Frequency of exclamation marks (`!`).
- `question_mark_count`: Frequency of question marks (`?`).
- `special_character_count`: Frequency of non-alphanumeric and non-whitespace characters.
- `line_count`: Count of line breaks / newline-separated lines.
- `emoji_count`: Count of Unicode emojis and pictographs across standard Unicode blocks (Emoticons, Transport, Symbols, Dingbats).

### Structural & Formatting Indicators
- `has_repeated_punctuation`: Boolean indicating consecutive punctuation sequences of length \(\ge 2\) (e.g., `!!!`, `???`, `$$$`).
- `max_consecutive_punctuation`: Maximum consecutive punctuation streak length in the message.
- `repeated_punctuation_count`: Number of distinct repeated punctuation clusters.
- `has_suspicious_unicode`: Boolean flag indicating presence of zero-width characters, directional overrides, mathematical alphanumeric characters, or mixed-script Latin/Cyrillic/Greek tokens.

### Entity Flags & Counts
- `has_url` & `url_count`: Detection and count of passive web URLs or web domains (`http://`, `https://`, `www.`).
- `has_phone_number` & `phone_count`: Detection and count of candidate phone numbers and mobile shortcodes.
- `has_email` & `email_count`: Detection and count of standard email addresses.
- `has_currency` & `currency_count`: Detection and count of monetary mentions (`₹`, `Rs`, `INR`, `$`, `£`, `€`, `rupees`, `dollars`, etc.).
- `amount_values`: List of parsed floating-point numeric currency magnitudes (e.g., `₹500` \(\to 500.0\), `10 lakh` \(\to 1,000,000.0\)).

### Behavioral Indicators (Signals Only)
- `otp_related`: Boolean flag indicating presence of explicit authentication terminology (e.g., `OTP`, `one-time password`, `verification code`, `security code`, `login code`).

---

## 4. URL Extraction Limitations

Implemented in `src/preprocessing/extract_urls`.
- **Passive Extraction Only**: URLs are identified via regex parsing and cleaned of trailing punctuation marks (e.g., `https://example.com.` \(\to\) `https://example.com`).
- **Zero Network Interaction**: Preprocessing never connects to any URL, never resolves DNS records, never crawls destination pages, and never performs SSL verification.
- **Limitation**: Obfuscated URLs lacking explicit schema or prefix (such as space-separated domains like `example [dot] com` or URL shorteners without protocol prefixes) are not resolved. Full deep URL inspection and reputation scoring is deferred to Phase 4.

---

## 5. Phone Number Extraction Limitations

Implemented in `src/preprocessing/extract_phone_numbers`.
- **Heuristic Filtering**: To minimize false positives, extraction applies pre-masking of URLs and emails, guards against currency prefixes (`$1,000`, `₹500`), unit suffixes (`100 points`, `24 hours`, `2024 years`), date delimiters (`2026-10-02`), and filters round magnitude numbers (`10000`).
- **Limitation**: Phone number patterns vary globally. The extractor captures standard international prefixes (`+91`, `+1`, `+44`), Indian 10-digit formats starting with 6-9, UK/US regional numbers, and 5-6 digit commercial SMS shortcodes. Unconventional spaces or alphanumeric phone words (e.g., `1-800-CALL-NOW`) require downstream domain logic.

---

## 6. Currency Extraction Limitations

Implemented in `src/preprocessing/extract_currencies`.
- **Multi-Currency Parsing**: Identifies Indian Rupee markers (`₹`, `Rs`, `INR`, `rupees`), US Dollars (`$`, `dollars`), British Pounds (`£`, `pounds`), and Euros (`€`, `euros`), expanding magnitude multipliers (`k`, `lakh`, `crore`, `million`).
- **Limitation**: Cryptographic currency references (e.g., `0.05 BTC`, `USDT transfers`) or informal colloquial payment slang without standard symbols are not parsed by this regex.
- **Non-Judgmental**: A currency mention does not denote a payment scam; benign receipts, utility notifications, and balance statements routinely mention amounts.

---

## 7. OTP Detection Limitations

Implemented in `src/preprocessing/is_otp_related`.
- **Token Matching**: Detects explicit phrases including `OTP`, `one-time password`, `one time passcode`, `verification code`, `security code`, and `authentication code`.
- **Limitation**: Genuine transactional SMS from banks (e.g., `Your OTP for transaction at Merchant X is 492019`) naturally match this pattern.
- **Signal Principle**: In isolation, an OTP notification is normal operational traffic. However, when combined in downstream modules with urgency, impersonation, or credential requests, it provides an essential feature signal.

---

## 8. Unicode Detection Limitations

Implemented in `src/preprocessing/has_suspicious_unicode`.
- **Detection Scope**: Flags:
  1. Zero-width and invisible characters (`\u200b`, `\ufeff`, `\u200d`, `\u2060`).
  2. Directional override formatting characters (`\u202e` RTL override) used in text-reversal spoofs.
  3. Mathematical Alphanumeric Symbols (`U+1D400` to `U+1D7FF`) used by spammers to bypass basic ASCII keyword filters (e.g., `𝑼𝑹𝑮𝑬𝑵𝑻`).
  4. Mixed script tokens combining Latin characters with visually identical Cyrillic (`\u0400-\u04FF`) or Greek (`\u0370-\u03FF`) homoglyphs within a single whitespace-delimited word.
- **Limitation**: Regional multi-lingual Indian texts (e.g., Hindi Devanagari, Tamil, Bengali) or standard non-Latin script messages are NOT flagged as suspicious. The detector specifically flags anomalous code-point mixtures and invisible control characters.

---

## 9. Why Original Text is Preserved

ScamShield AI is designed for transparent, explainable investigation.
- If a message is flagged as suspicious, the system must produce human-auditable evidence spans quoting the exact original wording (e.g., `"Your account will be suspended today"`).
- Destructive preprocessing that overwrites or discards original strings renders evidence verification impossible and invalidates character-offset indexing.
- Maintaining `text` as the immutable single source of truth ensures complete backward traceability for auditors, security analysts, and end users.

---

## 10. Why Aggressive Text Cleaning is Intentionally Avoided

Traditional NLP pipelines frequently apply:
- Stopword removal
- Stemming (e.g., Porter/Snowball)
- Lemmatization
- Punctuation stripping
- Number removal
- Case flattening

**Why this is prohibited in ScamShield AI:**
- **Punctuation is a Behavioral Signal**: Excessive exclamation marks (`!!!`) and question marks (`???`) indicate manufactured urgency and emotional pressure.
- **Numbers & Currencies are Target Assets**: Scam messages demand specific monetary values, deadlines, or OTP digits. Removing numbers strips the core payload of the attack.
- **Capitalization Reflects Coercion**: Spammers frequently employ all-caps (`URGENT NOTICE`, `ACCOUNT BLOCKED`) to elicit panic.
- **URLs and Contact Vectors are Channels**: Removing URLs or emails removes the exact redirection mechanism used to execute the fraud.

---

## 11. What is NOT Done in Phase 2

In strict adherence to project phasing:
- **NO ML Model Training**: No Logistic Regression, Naive Bayes, Decision Trees, or Neural Networks have been trained or evaluated.
- **NO TF-IDF Fitting**: TF-IDF vectorizers are not fitted against the corpus in this phase.
- **NO Embeddings / Vector Databases**: No sentence transformers, FAISS, ChromaDB, or dense vector stores are created.
- **NO LLMs / RAG**: No API calls to external language models, LangChain, or RAG architectures.
- **NO Network Calls**: Zero HTTP requests, DNS lookups, or web scraping.
- **NO Scam Classification**: No rules or thresholds determine whether a record is a scam.

---

## 12. Support for Later ML and Semantic Systems

This deterministic preprocessing infrastructure directly prepares the data foundation for future phases:
1. **Phase 3 (Classical ML Baseline)**: `analysis_text` feeds directly into n-gram TF-IDF vectorizers, while `features` can be stacked as dense numerical features alongside sparse text matrices.
2. **Phase 4 (URL & Threat Intelligence)**: Extracted passive `urls` feed into offline URL parsing, domain heuristics, and threat list matching.
3. **Phase 5 (Semantic & Novelty Detection)**: `normalized_text` provides clean, standardized text inputs for embedding generators, semantic cluster matching, and out-of-distribution anomaly detection.
4. **Phase 6 (Evidence & Explanation Engine)**: Preserved authoritative `text` guarantees accurate span highlighting and explainability when generating risk reports.

---

## 13. Verified Phase 2 Output Structure & Schema Contract

The verified output artifact is located at:
`data/processed/preprocessed/uci_sms_spam.jsonl`

### Record Relationship: Input vs. Output JSONL
- **Input File**: `data/processed/uci_sms_spam.jsonl` (5,574 lines)
- **Output File**: `data/processed/preprocessed/uci_sms_spam.jsonl` (5,574 lines)
- **Mapping**: Strictly 1-to-1 deterministic relationship.
- **Record Integrity**: Every input `sample_id` appears exactly once in identical order; 0 records dropped, 0 records duplicated.
- **Field Invariance**: All 23 canonical fields from Phase 1 are 100% identical between input and output.

### Authoritative vs. Derived Fields

| Field Name | Tier | Status | Description |
| :--- | :--- | :--- | :--- |
| `sample_id` | Canonical | **Authoritative** | Unique record identifier (e.g., `uci_sms_0001`). |
| `text` | Canonical | **Authoritative** | Original verbatim message string. Byte-for-byte immutable. |
| `language` | Canonical | **Authoritative** | Primary language code (`en`). |
| `source_type` | Canonical | **Authoritative** | Origin channel (`public_dataset`). |
| `label` | Canonical | **Authoritative** | Binary ground truth (`scam` / `non_scam`). |
| `scam_category` | Canonical | **Authoritative** | Descriptive category (`none`, `unknown`). |
| `tactics` | Canonical | **Authoritative** | Controlled vocabulary tactical indicators. |
| `evidence_spans` | Canonical | **Authoritative** | Verbatim substring evidence quotes. |
| `requested_action` | Canonical | **Authoritative** | Victim call to action. |
| `target_asset` | Canonical | **Authoritative** | Asset targeted for exploitation. |
| `urgency_level` | Canonical | **Authoritative** | Artificial urgency level. |
| `impersonated_entity` | Canonical | **Authoritative** | Pretended sender identity. |
| `has_url` | Canonical | **Authoritative** | Canonical URL presence flag. |
| `urls` | Canonical | **Authoritative** | List of extracted unvisited URLs. |
| `has_phone_number` | Canonical | **Authoritative** | Canonical phone presence flag. |
| `has_payment_request` | Canonical | **Authoritative** | Monetary payment request flag. |
| `source_reference` | Canonical | **Authoritative** | Provenance identifier. |
| `collection_date` | Canonical | **Authoritative** | Ingestion timestamp. |
| `label_confidence` | Canonical | **Authoritative** | Annotator label confidence. |
| `annotator_id` | Canonical | **Authoritative** | Annotator / pipeline ID. |
| `pattern_group_id` | Canonical | **Authoritative** | Campaign cluster ID for leakage splitting. |
| `known_unknown_status` | Canonical | **Authoritative** | Novelty evaluation tier (`known`). |
| `notes` | Canonical | **Authoritative** | Provenance notes. |
| `normalized_text` | Preprocessing | *Derived* | Conservative Unicode NFKC + whitespace normalized representation. |
| `analysis_text` | Preprocessing | *Derived* | Lowercase derived representation for TF-IDF / NLP modeling. |
| `features` | Preprocessing | *Derived* | Dense dictionary of 25 deterministic numerical/boolean signals for ML. |
| `entities` | Preprocessing | *Derived* | Structured dictionary of passive extracted entity lists (`urls`, `phone_numbers`, `emails`, `currency_mentions`). |

### Exact Preprocessed JSONL Record Structure Example

```json
{
  "sample_id": "uci_sms_0013",
  "text": "URGENT! You have won a 1 week FREE membership in our £100,000 Prize Jackpot! Txt the word: CLAIM to No: 81010 T&C www.dbuk.net LCCLTD POBOX 4403LDNW1A7RW18",
  "language": "en",
  "source_type": "public_dataset",
  "label": "scam",
  "scam_category": "unknown",
  "tactics": [],
  "evidence_spans": [],
  "requested_action": "none",
  "target_asset": "none",
  "urgency_level": "none",
  "impersonated_entity": "none",
  "has_url": true,
  "urls": ["www.dbuk.net"],
  "has_phone_number": true,
  "has_payment_request": false,
  "source_reference": "src_uci_sms_spam_228#L13",
  "collection_date": "2026-10-02",
  "label_confidence": "medium",
  "annotator_id": "uci_corpus_import",
  "pattern_group_id": "grp_uci_unassigned_13",
  "known_unknown_status": "known",
  "notes": "Normalized from UCI SMS Spam Collection (row 13)...",
  "normalized_text": "URGENT! You have won a 1 week FREE membership in our £100,000 Prize Jackpot! Txt the word: CLAIM to No: 81010 T&C www.dbuk.net LCCLTD POBOX 4403LDNW1A7RW18",
  "analysis_text": "urgent! you have won a 1 week free membership in our £100,000 prize jackpot! txt the word: claim to no: 81010 t&c www.dbuk.net lccltd pobox 4403ldnw1a7rw18",
  "features": {
    "character_count": 155,
    "word_count": 26,
    "digit_count": 20,
    "uppercase_count": 40,
    "uppercase_ratio": 0.2581,
    "digit_ratio": 0.129,
    "exclamation_count": 2,
    "question_mark_count": 0,
    "special_character_count": 9,
    "line_count": 1,
    "emoji_count": 0,
    "has_url": true,
    "url_count": 1,
    "has_phone_number": true,
    "phone_count": 1,
    "has_email": false,
    "email_count": 0,
    "has_currency": true,
    "currency_count": 1,
    "amount_values": [100000.0],
    "otp_related": false,
    "has_repeated_punctuation": false,
    "max_consecutive_punctuation": 0,
    "repeated_punctuation_count": 0,
    "has_suspicious_unicode": false
  },
  "entities": {
    "urls": ["www.dbuk.net"],
    "phone_numbers": ["81010"],
    "emails": [],
    "currency_mentions": ["£100,000"]
  }
}
```

### Deterministic & Isolated Execution
- The preprocessing pipeline is fully deterministic: `preprocess_record(r) == preprocess_record(r)`.
- Features never duplicate or overwrite ground-truth annotations (no `features.label`, no `features.tactics`).
- Preprocessing produces zero network calls, requires zero API keys, and fits zero machine learning models.

