# ScamShield AI — Phase 9B Visual Dataset Corpus

This directory contains the controlled visual classification dataset for **Phase 9B: Visual Scam Classification**.

## Directory Structure

```text
data/visual/
├── metadata/
│   ├── dataset_manifest.json   # Full dataset metadata, labels, and partition records
│   └── leakage_report.json     # Forensic certification proving 0 cross-split leakage
└── synthetic/
    ├── legit_delivery_01.png   # Group A: Benign delivery tracking stepper
    ├── legit_delivery_02.png
    ├── legit_statement_01.png  # Group A: Benign bank statement table
    ├── legit_statement_02.png
    ├── legit_promo_01.png      # Group A: Benign retail promotional flyer
    ├── legit_promo_02.png
    ├── legit_chat_01.png       # Group A: Benign personal chat messenger
    ├── legit_chat_02.png
    ├── scam_acct_lock_01.png   # Group B: Urgent phishing lockout modal
    ├── scam_acct_lock_02.png
    ├── scam_lottery_01.png     # Group B: Lottery winner scratchcard voucher
    ├── scam_lottery_02.png
    ├── scam_kyc_01.png         # Group B: Phishing KYC input form
    ├── scam_kyc_02.png
    ├── scam_qr_phish_01.png    # Group B: Deceptive QR refund phish screen
    ├── scam_qr_phish_02.png
    ├── hard_neg_qr_01.png      # Group C: Legitimate retail POS QR checkout
    ├── hard_neg_qr_02.png      # Group C: Legitimate transit QR ticket
    ├── hard_neg_otp_01.png     # Group C: Legitimate bank OTP verification dialog
    ├── hard_neg_otp_02.png     # Group C: Legitimate MFA security login prompt
    ├── hard_neg_alert_01.png   # Group C: Legitimate bank fraud monitoring alert
    ├── hard_neg_alert_02.png   # Group C: Legitimate Google security notice
    ├── hard_neg_card_01.png    # Group C: Legitimate credit card billing summary
    ├── hard_neg_card_02.png    # Group C: Legitimate utility billing reminder
    ├── paired_layout_scam.png  # Paired layout variant (scam text in alert template)
    ├── paired_layout_legit.png # Paired layout variant (benign text in identical template)
    ├── paired_text_styled.png  # Paired text variant (scam text in styled red template)
    └── paired_text_plain.png   # Paired text variant (same scam text in plain note)
```

## Dataset Specifications

- **Total Samples**: 28
- **Classes**:
  - `scam`: 10
  - `non_scam`: 18 (including 8 Hard Negatives)
- **Splits**:
  - `train`: 16 samples (10 non-scam, 6 scam)
  - `val`: 4 samples (2 non-scam, 2 scam)
  - `test`: 8 samples (5 non-scam, 3 scam)
- **Data Leakage Certification**:
  - Group-isolated partitioning: 0 group overlap.
  - SHA-256 exact overlap: 0.
  - 64-bit dHash perceptual overlap (\( \le 2 \) bits): 0.

## Reproducibility

To regenerate or verify the dataset:
```bash
python -m src.vision --build-dataset
```
