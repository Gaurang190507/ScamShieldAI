# Raw Dataset: UCI SMS Spam Collection 📦

## 1. Provenance & Source Metadata
- **Dataset Name**: SMS Spam Collection v.1
- **Official Repository**: UCI Machine Learning Repository
- **Source URL**: https://archive.ics.uci.edu/dataset/228/sms%2Bspam%2Bcollection
- **Download Archive**: `https://archive.ics.uci.edu/static/public/228/sms+spam+collection.zip`
- **Acquisition Date**: 2026-10-02
- **License**: Creative Commons Attribution 4.0 International (CC BY 4.0)
- **Creators / Contributors**: Tiago A. Almeida, José María Gómez Hidalgo

## 2. File Verification & Checksums
The files in this directory are preserved in their exact, pristine, unmodified state as distributed by UCI:

| File Name | File Size | SHA-256 Checksum |
| :--- | :--- | :--- |
| `sms_spam_collection.zip` | 203,415 bytes | `b231ff68ea5b115ff67d602a8ebdc7190e5dd90f72dd3d1ceee8be89a42f5343` |
| `SMSSpamCollection` | 477,907 bytes | `7d039a24a6083ed9ef0f806ebad56bbb976e3aeb8de05669173bfdc4996c239d` |
| `readme` | 5,869 bytes | `b41bb14a7ff9562719a79fa4f51e06531393693f18548c26f0f15c7e1088c4d6` |

## 3. Dataset Characteristics
- **Total Records**: 5,574 SMS messages.
- **Format**: Tab-separated plaintext (`<label>\t<message>`).
- **Original Labels**:
  - `ham` (legitimate): 4,827 messages (~86.6%)
  - `spam` (unsolicited / marketing / scams): 747 messages (~13.4%)
- **Language**: English (`en`).
- **Original Sources**: UK Grumbletext forum, Caroline Tag's NUS SMS Corpus, and Jon Noel's mobile research corpus (circa 2011–2012).

## 4. Downstream Ingestion & Normalization
The ingestion pipeline (`src/data/ingest_uci_sms.py`) maps these raw records into ScamShield's internal schema (`data/processed/uci_sms_spam.jsonl`):
- `ham` ➔ `non_scam` (with `scam_category = "none"`)
- `spam` ➔ `scam` (with `scam_category = "unknown"`)
- **Important**: This label translation is a *dataset-specific normalization assumption*. Spam and scams overlap heavily in SMS communications, but not all spam messages are fraudulent scams.
- `tactics` and `evidence_spans` are initialized as empty lists (`[]`) because the original UCI dataset does not include fine-grained behavioral or tactical annotations. We do not synthesize or fake annotations during ingestion.

## 5. Known Limitations
1. **Historical Context**: Collected between 2011 and 2012; reflects older mobile SMS patterns rather than modern WhatsApp, Telegram, or social media vectors.
2. **Geographical Focus**: Primarily UK and Singapore university student SMS traffic; contains zero Indian or regional dialect (Hinglish) nuances.
3. **No Campaign / Pattern Groups**: The original corpus does not track attack campaign families or template clusters.
4. **Spam vs. Scam Discrepancy**: Many spam records are commercial marketing broadcasts rather than social engineering or credential harvesting attacks.
