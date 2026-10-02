"""Safe, reproducible ingestion and normalization pipeline for the UCI SMS Spam Collection.

IMPORTANT OPERATIONAL PRINCIPLES:
---------------------------------
1. Untrusted Text: Message contents are treated strictly as untrusted text.
   - NO network requests are made.
   - NO URLs found in messages are visited, resolved, or requested.
   - NO scripts or instructions inside messages are executed.
2. Label Normalization Assumption:
   - 'ham' -> 'non_scam'
   - 'spam' -> 'scam'
   - This mapping is a DATASET-SPECIFIC NORMALIZATION ASSUMPTION. Commercial spam
     and fraudulent scams overlap heavily in historical SMS, but are not identical.
3. Zero Fabrication:
   - 'tactics' and 'evidence_spans' are left empty ([]) because the UCI dataset
     provides no tactic annotations. We do not synthesize or fake annotations.
   - 'pattern_group_id' is assigned to documented individual unassigned placeholders
     ('grp_uci_unassigned_{idx}') because the dataset provides no campaign groups.
"""

from pathlib import Path
import re
from typing import Dict, Any, List, Optional, Tuple
from urllib.parse import urlparse

from .dataset_schema import (
    Label,
    SourceType,
    ScamCategory,
    RequestedAction,
    TargetAsset,
    UrgencyLevel,
    ImpersonatedEntity,
    LabelConfidence,
    KnownUnknownStatus,
)
from .dataset_validator import DatasetValidator
from .data_loader import save_dataset
from .dataset_stats import generate_dataset_statistics, format_statistics_report
from .duplicate_detector import detect_duplicates
import pandas as pd


# Deterministic URL matching pattern (never contacted over network)
URL_REGEX = re.compile(
    r"(?:https?://|www\.)[^\s/$.?#].[^\s]*",
    re.IGNORECASE,
)

# Standard mobile / UK shortcode & international phone regex
PHONE_REGEX = re.compile(
    r"(?:\+?\d{1,3}[-.\s]?)?\(?\d{3,5}\)?[-.\s]?\d{3,5}[-.\s]?\d{3,6}\b|\b\d{5,7}\b"
)

# Deterministic fee / payment request indicators
PAYMENT_CUES_REGEX = re.compile(
    r"\b(credit|debit|cost|fee|charge|£\d+|\$\d+|\b\d+\s*p\b|ppm|pay\s+now|subscription)\b",
    re.I,
)


def extract_urls(text: str) -> List[str]:
    """Safely extracts URL strings without network requests or domain resolution."""
    if not isinstance(text, str):
        return []
    matches = URL_REGEX.findall(text)
    valid_urls = []
    for m in matches:
        # Strip trailing punctuation commonly appended to URLs in natural language
        clean_url = m.rstrip(".,;!?'\")>]}")
        parsed = urlparse(clean_url)
        if parsed.scheme or parsed.netloc or parsed.path:
            valid_urls.append(clean_url)
    return valid_urls


def extract_phone_numbers(text: str) -> List[str]:
    """Extracts telephone numbers and SMS shortcodes from text."""
    if not isinstance(text, str):
        return []
    return PHONE_REGEX.findall(text)


def has_payment_cue(text: str) -> bool:
    """Detects explicit payment, tariff, or fee cues."""
    if not isinstance(text, str):
        return False
    return bool(PAYMENT_CUES_REGEX.search(text))


def parse_uci_line(line: str, line_num: int) -> Tuple[str, str]:
    """Parses a single tab-delimited line from SMSSpamCollection.

    Args:
        line: Raw line string.
        line_num: 1-indexed line number for error reporting.

    Returns:
        Tuple of (original_label, raw_text).

    Raises:
        ValueError: If line is empty or missing tab delimiter.
    """
    clean_line = line.strip("\r\n")
    if not clean_line.strip():
        raise ValueError(f"Line {line_num} is empty.")

    parts = clean_line.split("\t", 1)
    if len(parts) != 2:
        raise ValueError(
            f"Line {line_num} does not contain exactly two tab-separated fields. Found {len(parts)}."
        )

    original_label = parts[0].strip().lower()
    raw_text = parts[1].strip()

    if not raw_text:
        raise ValueError(f"Line {line_num} contains an empty message text.")

    if original_label not in ("ham", "spam"):
        raise ValueError(
            f"Line {line_num} contains unrecognized original label '{original_label}'. Expected 'ham' or 'spam'."
        )

    return original_label, raw_text


def normalize_uci_record(
    original_label: str, raw_text: str, line_num: int
) -> Dict[str, Any]:
    """Transforms raw UCI fields into ScamShield AI standardized schema record."""
    if original_label == "ham":
        normalized_label = Label.NON_SCAM.value
        scam_category = ScamCategory.NONE.value
        label_confidence = LabelConfidence.HIGH.value
    else:  # spam
        normalized_label = Label.SCAM.value
        scam_category = ScamCategory.UNKNOWN.value
        # Medium confidence reflecting the assumption that not all spam is a scam
        label_confidence = LabelConfidence.MEDIUM.value

    extracted_urls = extract_urls(raw_text)
    extracted_phones = extract_phone_numbers(raw_text)
    payment_flag = has_payment_cue(raw_text)

    return {
        "sample_id": f"uci_sms_{line_num:04d}",
        "text": raw_text,
        "language": "en",
        "source_type": SourceType.PUBLIC_DATASET.value,
        "label": normalized_label,
        "scam_category": scam_category,
        "tactics": [],  # Intentionally empty: no synthetic or fabricated annotations
        "evidence_spans": [],  # Intentionally empty: no fabricated spans
        "requested_action": RequestedAction.NONE.value,
        "target_asset": TargetAsset.NONE.value,
        "urgency_level": UrgencyLevel.NONE.value,
        "impersonated_entity": ImpersonatedEntity.NONE.value,
        "has_url": bool(len(extracted_urls) > 0),
        "urls": extracted_urls,
        "has_phone_number": bool(len(extracted_phones) > 0),
        "has_payment_request": payment_flag,
        "source_reference": f"src_uci_sms_spam_228#L{line_num}",
        "collection_date": "2026-10-02",
        "label_confidence": label_confidence,
        "annotator_id": "uci_corpus_import",
        "pattern_group_id": f"grp_uci_unassigned_{line_num}",
        "known_unknown_status": KnownUnknownStatus.KNOWN.value,
        "notes": (
            f"Normalized from UCI SMS Spam Collection (row {line_num}). "
            f"Original label: '{original_label}'. "
            "Normalization assumption: 'spam' mapped to 'scam' for baseline text modeling. "
            "No tactical or evidence annotations provided in original source."
        ),
    }


def ingest_uci_sms(
    raw_path: Optional[Path] = None,
    output_path: Optional[Path] = None,
    validate: bool = True,
) -> Dict[str, Any]:
    """Executes end-to-end ingestion of the UCI SMS Spam Collection.

    Args:
        raw_path: Path to raw SMSSpamCollection file. Defaults to project location.
        output_path: Target path for normalized .jsonl. Defaults to data/processed/uci_sms_spam.jsonl.
        validate: Whether to run DatasetValidator on the normalized collection.

    Returns:
        Summary dictionary containing counts, distribution metrics, and validation status.
    """
    root_dir = Path(__file__).resolve().parents[2]
    raw_file = raw_path or (
        root_dir / "data" / "raw" / "external" / "uci_sms_spam" / "SMSSpamCollection"
    )
    out_file = output_path or (root_dir / "data" / "processed" / "uci_sms_spam.jsonl")

    if not raw_file.is_file():
        raise FileNotFoundError(
            f"Raw UCI SMS Spam file not found at: {raw_file}. Ensure raw data is acquired."
        )

    records: List[Dict[str, Any]] = []
    ham_count = 0
    spam_count = 0
    url_count = 0
    phone_count = 0
    payment_count = 0

    with open(raw_file, "r", encoding="utf-8") as f:
        for idx, line in enumerate(f, start=1):
            line_str = line.strip("\r\n")
            if not line_str:
                continue
            orig_lbl, text = parse_uci_line(line_str, line_num=idx)
            if orig_lbl == "ham":
                ham_count += 1
            else:
                spam_count += 1

            rec = normalize_uci_record(orig_lbl, text, line_num=idx)
            if rec["has_url"]:
                url_count += 1
            if rec["has_phone_number"]:
                phone_count += 1
            if rec["has_payment_request"]:
                payment_count += 1

            records.append(rec)

    df_normalized = pd.DataFrame(records)

    # Validate against ScamShield AI schema
    validator = DatasetValidator()
    validation_res = validator.validate_dataset(records)

    if validate and not validation_res.is_valid:
        raise ValueError(
            f"Validation failed during UCI SMS ingestion:\n{validation_res.summary()}"
        )

    # Save to canonical JSONL
    save_dataset(
        df_normalized,
        out_file,
        format="jsonl",
        validate=False,  # Already validated above
    )

    # Duplicate audit
    dup_report = detect_duplicates(records)

    summary = {
        "raw_file": str(raw_file),
        "output_file": str(out_file),
        "total_records": len(records),
        "original_ham_count": ham_count,
        "original_spam_count": spam_count,
        "normalized_non_scam_count": ham_count,
        "normalized_scam_count": spam_count,
        "records_with_urls": url_count,
        "records_with_phone_numbers": phone_count,
        "records_with_payment_indicators": payment_count,
        "validation_passed": validation_res.is_valid,
        "validation_errors_count": len(validation_res.errors),
        "exact_duplicates": dup_report.total_exact_duplicates,
        "normalized_duplicates": dup_report.total_normalized_duplicates,
    }

    return summary


def print_ingestion_summary(summary: Dict[str, Any]) -> None:
    """Prints a clear, formatted summary report for investigators."""
    print("==================================================")
    print("    SCAMSHIELD AI: UCI SMS INGESTION SUMMARY      ")
    print("==================================================")
    print(f"Total Raw Records Ingested:        {summary['total_records']}")
    print(f"Original Ham (-> non_scam):        {summary['original_ham_count']}")
    print(f"Original Spam (-> scam):           {summary['original_spam_count']}")
    print(f"Records with Extracted URLs:       {summary['records_with_urls']}")
    print(f"Records with Phone Numbers:        {summary['records_with_phone_numbers']}")
    print(f"Records with Payment Indicators:   {summary['records_with_payment_indicators']}")
    print("--------------------------------------------------")
    print(f"Schema Validation Passed:          {summary['validation_passed']}")
    print(f"Validation Errors:                 {summary['validation_errors_count']}")
    print(f"Exact Duplicate Messages:          {summary['exact_duplicates']}")
    print(f"Normalized Duplicate Messages:     {summary['normalized_duplicates']}")
    print(f"Output File Written:               {summary['output_file']}")
    print("==================================================")


if __name__ == "__main__":
    res = ingest_uci_sms()
    print_ingestion_summary(res)
