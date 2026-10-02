"""Unified preprocessing and deterministic feature extraction pipeline."""

import json
from pathlib import Path
from typing import Union, Dict, Any, Optional

from .schemas import PreprocessedMessage, ExtractedEntities, TextFeatures
from .normalize import build_normalized_text, build_analysis_text
from .extract_entities import extract_all_entities
from .extract_features import extract_text_features


def preprocess_message(
    message: Union[str, Dict[str, Any]],
    sample_id: Optional[str] = None,
) -> PreprocessedMessage:
    """Preprocesses a single message, preserving authoritative raw text and extracting signals.

    Args:
        message: Raw message text string, or a dictionary containing 'text' and 'sample_id'.
        sample_id: Optional unique identifier. Defaults to record sample_id or 'sample_001'.

    Returns:
        PreprocessedMessage instance containing text, normalized_text, analysis_text,
        features, and entities.
    """
    if isinstance(message, dict):
        raw_text = message.get("text", "")
        s_id = str(sample_id or message.get("sample_id", "sample_001"))
    else:
        raw_text = str(message) if message is not None else ""
        s_id = str(sample_id or "sample_001")

    # Preserve exact raw text as the authoritative ground truth for evidence & auditing
    text = raw_text

    # Conservative normalization
    normalized_text = build_normalized_text(text)

    # Derived lowercase representation for classical NLP modeling
    analysis_text = build_analysis_text(text)

    # Deterministic entity extraction
    entities = extract_all_entities(text)

    # Deterministic feature calculation
    features = extract_text_features(text, entities=entities)

    return PreprocessedMessage(
        sample_id=s_id,
        text=text,
        normalized_text=normalized_text,
        analysis_text=analysis_text,
        features=features,
        entities=entities,
    )


def preprocess_record(record: Dict[str, Any]) -> Dict[str, Any]:
    """Augments an existing dataset record with preprocessing representations and features.

    Preserves all existing dataset columns (label, source_type, tactics, etc.).

    Args:
        record: Original dictionary record.

    Returns:
        Augmented dictionary record including normalized_text, analysis_text, features, and entities.
    """
    prep = preprocess_message(record, sample_id=record.get("sample_id"))
    out = dict(record)
    out["normalized_text"] = prep.normalized_text
    out["analysis_text"] = prep.analysis_text
    out["features"] = prep.features.to_dict()
    out["entities"] = prep.entities.to_dict()
    return out


def preprocess_dataset_file(
    input_path: Union[str, Path],
    output_path: Union[str, Path],
) -> Dict[str, Any]:
    """Processes an entire JSONL dataset file and writes the preprocessed derived artifact.

    Args:
        input_path: Path to input JSONL dataset.
        output_path: Target path for preprocessed JSONL artifact.

    Returns:
        Summary statistics dictionary.
    """
    in_file = Path(input_path).resolve()
    out_file = Path(output_path).resolve()

    if not in_file.is_file():
        raise FileNotFoundError(f"Input dataset file not found at: {in_file}")

    out_file.parent.mkdir(parents=True, exist_ok=True)

    total_records = 0
    total_urls = 0
    total_phones = 0
    total_emails = 0
    total_currencies = 0
    total_otp = 0
    total_suspicious_unicode = 0

    with open(in_file, "r", encoding="utf-8") as in_f, open(out_file, "w", encoding="utf-8") as out_f:
        for line in in_f:
            line_str = line.strip()
            if not line_str:
                continue
            rec = json.loads(line_str)
            augmented = preprocess_record(rec)

            total_records += 1
            if augmented["features"]["has_url"]:
                total_urls += 1
            if augmented["features"]["has_phone_number"]:
                total_phones += 1
            if augmented["features"]["has_email"]:
                total_emails += 1
            if augmented["features"]["has_currency"]:
                total_currencies += 1
            if augmented["features"]["otp_related"]:
                total_otp += 1
            if augmented["features"]["has_suspicious_unicode"]:
                total_suspicious_unicode += 1

            out_f.write(json.dumps(augmented, ensure_ascii=False) + "\n")

    return {
        "input_path": str(in_file),
        "output_path": str(out_file),
        "total_records": total_records,
        "records_with_urls": total_urls,
        "records_with_phone_numbers": total_phones,
        "records_with_emails": total_emails,
        "records_with_currencies": total_currencies,
        "records_with_otp": total_otp,
        "records_with_suspicious_unicode": total_suspicious_unicode,
    }


if __name__ == "__main__":
    root_dir = Path(__file__).resolve().parents[2]
    in_path = root_dir / "data" / "processed" / "uci_sms_spam.jsonl"
    out_path = root_dir / "data" / "processed" / "preprocessed" / "uci_sms_spam.jsonl"

    print("Running ScamShield AI Phase 2 Preprocessing Pipeline...")
    stats = preprocess_dataset_file(in_path, out_path)
    print("==================================================")
    print("       PHASE 2 PREPROCESSING SUMMARY              ")
    print("==================================================")
    print(f"Total Records Processed:           {stats['total_records']}")
    print(f"Records with Extracted URLs:       {stats['records_with_urls']}")
    print(f"Records with Phone Numbers:        {stats['records_with_phone_numbers']}")
    print(f"Records with Emails:               {stats['records_with_emails']}")
    print(f"Records with Currency Mentions:    {stats['records_with_currencies']}")
    print(f"Records with OTP-related Signals:  {stats['records_with_otp']}")
    print(f"Records with Suspicious Unicode:   {stats['records_with_suspicious_unicode']}")
    print(f"Output Written To:                 {stats['output_path']}")
    print("==================================================")
