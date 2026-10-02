"""CLI entry point for ScamShield AI preprocessing pipeline: python -m src.preprocessing"""

from pathlib import Path
from .preprocess_message import preprocess_dataset_file


def main() -> None:
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


if __name__ == "__main__":
    main()
