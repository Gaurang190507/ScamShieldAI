# ScamShield AI — Phase 9B Hard-Negative Vulnerability Analysis

## Objective
Assess the vulnerability of visual classification to false accusations on benign UI layouts
that exhibit visual patterns typically associated with scams (QR codes, urgent security warnings,
OTP prompts, credit card billing).

## Empirical Results

Total Hard Negative Samples: 8

### False Positive Counts by Modality
- **Visual-Only Classifier**: 4 false positives (50.0%)
- **Text-Only Classifier**: 0 false positives (0.0%)
- **Multimodal Fusion**: 0 false positives (0.0%)

### Sample-by-Sample Breakdown

| Sample ID | Scenario | Visual Pred (Prob) | Text Pred (Prob) | Fusion Pred (Prob) |
|---|---|:---:|:---:|:---:|
| `hard_neg_qr_01` | qr_payment | scam (0.24) | non_scam (0.13) | non_scam (0.16) |
| `hard_neg_qr_02` | qr_payment | scam (0.25) | non_scam (0.27) | non_scam (0.26) |
| `hard_neg_otp_01` | otp_alert | scam (0.32) | non_scam (0.19) | non_scam (0.23) |
| `hard_neg_otp_02` | otp_alert | scam (0.34) | non_scam (0.22) | non_scam (0.25) |
| `hard_neg_alert_01` | security_alert | non_scam (0.08) | non_scam (0.20) | non_scam (0.16) |
| `hard_neg_alert_02` | security_alert | non_scam (0.08) | non_scam (0.07) | non_scam (0.07) |
| `hard_neg_card_01` | card_payment | non_scam (0.09) | non_scam (0.18) | non_scam (0.15) |
| `hard_neg_card_02` | card_payment | non_scam (0.09) | non_scam (0.22) | non_scam (0.18) |

## Key Forensic Insights
1. **QR Code Conflation**: Visual edge detection reliably identifies high-density square grids,
   but cannot distinguish whether the QR code points to an authorized retail checkout or a fraudulent refund URL.
2. **Urgency Banner Bias**: Red accent headers and high-contrast alert boxes exist in official
   bank fraud notifications as well as phishing pages. Relying strictly on red saturation or header banners
   produces false alarms on security warnings.
3. **Recommendation**: Visual evidence should only be treated as contextual signals and must be
   anchored to lexical and URL verification before assigning high risk.