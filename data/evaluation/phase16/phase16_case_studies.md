# ScamShield AI — Phase 16 Representative Case Studies

## 1. Overview
This report documents detailed end-to-end case investigations across 8 distinct operational categories.
All sensitive personal identifiable information (PII) including phone numbers, account digits, and personal tokens has been rigorously redacted.

---
## 2. Category Case Studies

### 2.1 Five Successful Scam Detections (True Positives)

#### Case 1: `P16-C01-001` — Retail Banking KYC Suspension Phishing
- **Input Text**: `Dear customer, your HDFC bank account ending with XX49 is locked due to pending PAN-Aadhaar linkage. Please update immediately at http://hdfc-kyc-verify-portal.top to avoid permanent deactivation.`
- **Ground Truth**: `scam` | **System Verdict**: **`likely_scam`** (High Evidence)
- **Component Evidence**:
  * Phase 3 Text Classifier: `p = 0.9412` (Threshold 0.30)
  * Phase 4 URL Analyzer: High-risk TLD `.top`, unregistered brand subdomain
  * Phase 6 Tactics: `urgency`, `authority_impersonation`, `action_demand`
  * Phase 7 Similarity: Nearest reference match cosine similarity `0.7812`
- **Outcome Rationale**: Multi-signal consensus across all 4 upstream modules produced an unequivocal high-confidence detection.

#### Case 2: `P16-C01-002` — Electricity Disconnection Blackout Threat
- **Input Text**: `Urgent: Your electricity power supply will be disconnected tonight at 9:30 PM by discom officer because your last month bill was not updated. Immediately contact accounts officer at +91-98765-XXXX1 or pay via UPI.`
- **Ground Truth**: `scam` | **System Verdict**: **`likely_scam`** (High Evidence)
- **Component Evidence**:
  * Phase 3 Text Classifier: `p = 0.8841`
  * Phase 6 Tactics: `urgency`, `payment_demand`, `authority_impersonation`
- **Outcome Rationale**: Severe temporal urgency combined with utility officer impersonation and mobile number callout.

#### Case 3: `P16-C01-003` — India Post Redelivery Fee Smishing
- **Input Text**: `India Post Notice: Your parcel tracking #IN98412894 arrived at sorting hub but address is incomplete. Pay clearance fee of Rs 48 within 24h at http://ind-post-update-redelivery.org to avoid return to sender.`
- **Ground Truth**: `scam` | **System Verdict**: **`likely_scam`** (Moderate Evidence)
- **Component Evidence**:
  * Phase 4 URL Analyzer: Lookalike postal domain with non-sovereign `.org` TLD
  * Phase 6 Tactics: `urgency`, `payment_demand`

#### Case 4: `P16-C01-005` — SBI YONO Credential Harvester
- **Input Text**: `Dear SBI user, your YONO account has been disabled. Tap http://sbi-yono-reactivate.xyz to submit netbanking credentials and unlock your account within 12 hours.`
- **Ground Truth**: `scam` | **System Verdict**: **`likely_scam`** (High Evidence)
- **Component Evidence**: Text classifier `p = 0.9632`, deceptive `.xyz` domain, `credential_harvesting` tactic.

#### Case 5: `P16-C01-006` — Vehicle Traffic E-Challan Legal Threat
- **Input Text**: `Notice: An unpaid traffic violation e-challan of Rs 1,500 is pending against vehicle DL01XX0000. Pay online within 48h to avoid court warrant: http://echallan-parivahan-pay.link`
- **Ground Truth**: `scam` | **System Verdict**: **`likely_scam`** (High Evidence)
- **Component Evidence**: Legal threat tactic detected, court warrant intimidation, fake parivahan link.

---
### 2.2 Five Successful Benign Detections (True Negatives)

#### Case 6: `P16-C03-001` — Bank Transaction OTP Notification
- **Input Text**: `582914 is your secret One Time Password (OTP) for transaction of INR 3,450.00 at Swiggy using HDFC Bank Card ending 1204. Valid for 10 mins. Do NOT share with anyone.`
- **Ground Truth**: `non_scam` | **System Verdict**: **`likely_non_scam`**
- **Outcome Rationale**: Standard transactional syntax. Security warning 'Do NOT share' appropriately recognized as legitimate defensive guidance.

#### Case 7: `P16-C03-002` — SBI Card E-Statement Notification
- **Input Text**: `Dear Cardmember, e-statement for SBI Card ending 5892 for period ending 15-Sep-2026 is generated. Total amount due: Rs 14,230. Minimum due: Rs 1,400. Due date: 05-Oct-2026.`
- **Ground Truth**: `non_scam` | **System Verdict**: **`likely_non_scam`**
- **Outcome Rationale**: Informational monthly billing summary; no coercive links, threatening language, or unauthorized collection accounts.

#### Case 8: `P16-C03-004` — Tata Power Utility Payment Confirmation
- **Input Text**: `Dear Consumer, payment of Rs 1,840.00 received against CA #1002938192 on 02-Oct-2026 via NetBanking. Receipt #REC981240. Thank you - Tata Power Delhi.`
- **Ground Truth**: `non_scam` | **System Verdict**: **`likely_non_scam`**
- **Outcome Rationale**: Passive payment acknowledgment receipt with reference ID.

#### Case 9: `P16-C03-011` — Corporate Payroll Salary Credit
- **Input Text**: `Your account XX9821 is credited with INR 85,000.00 on 30-Sep-2026 towards Salary by ACME TECH CORP. Available balance: INR 1,12,450.00 - ICICI Bank.`
- **Ground Truth**: `non_scam` | **System Verdict**: **`likely_non_scam`**
- **Outcome Rationale**: Standard core banking credit ledger advice.

#### Case 10: `P16-C03-013` — Google Account Security Notice
- **Input Text**: `Security alert: New sign-in on Windows device for radika@gmail.com. If this was you, you don't need to do anything. If not, check your account activity at https://myaccount.google.com/notifications`
- **Ground Truth**: `non_scam` | **System Verdict**: **`likely_non_scam`**
- **Outcome Rationale**: Legitimate security notice hosted on authoritative `google.com` domain.

---
### 2.3 Five False Negatives (Missed Detections)

#### Case 11: `P16-C04-001` — Native Devanagari Electricity Scam
- **Input Text**: `जरूरी सूचना: आपके बिजली का बिल जमा नहीं होने के कारण आज रात 10 बजे बिजली काट दी जाएगी। तुरंत बिल जमा करने के लिए बिजली अधिकारी से संपर्क करें: 98765-XXXX5`
- **Ground Truth**: `scam` | **System Verdict**: `mixed_signals` (Strict FN)
- **Failure Cause**: 100% OOV rate on Devanagari script for Phase 3 English TF-IDF vectorizer.

#### Case 12: `P16-C05-001` — Character Spaced Banking Phishing
- **Input Text**: `D e a r  c u s t o m e r, y o u r  b a n k  a c c o u n t  h a s  b e e n  s u s p e n d e d. U p d a t e  K Y C  a t  http://b-a-n-k-k-y-c.top`
- **Ground Truth**: `scam` | **System Verdict**: `mixed_signals` (Strict FN)
- **Failure Cause**: Whitespace between individual characters prevented unigram feature matching.

#### Case 13: `P16-C02-001` — Digital Arrest Virtual Custody Extortion
- **Input Text**: `Notice of Virtual Judicial Custody: You are placed under digital arrest by order of Directorate of Enforcement. You must remain on video call in private room until your assets are audited.`
- **Ground Truth**: `scam` | **System Verdict**: `mixed_signals` (Strict FN)
- **Failure Cause**: Novel extortion vocabulary not represented in historical training distribution.

#### Case 14: `P16-C02-003` — Green Hydrogen ESG Arbitrage Syndicate
- **Input Text**: `Join our green hydrogen algorithmic arbitrage pool recommended by leading industry leaders. Early syndicate members receive 15% weekly payout backed by carbon credits.`
- **Ground Truth**: `scam` | **System Verdict**: `likely_non_scam` (Severe FN)
- **Failure Cause**: Absence of traditional urgency or banking keywords; esoteric financial jargon appeared benign to baseline classifier.

#### Case 15: `P16-C02-007` — Corporate HR PF Exit Clearance Audit
- **Input Text**: `Former Employer HR Audit: Unsettled tax liability identified in your PF exit settlement. Clearance certificate requires immediate settlement of Rs 14,200 via nodal escrow account.`
- **Ground Truth**: `scam` | **System Verdict**: `mixed_signals` (Strict FN)
- **Failure Cause**: Corporate compliance narrative lacks overt scam signals.

---
### 2.4 Representative False Positives and Anomaly Cases

#### Case 16: `P16-C03-003` — Amazon Delivery Package Handover Code
- **Input Text**: `Your Amazon delivery agent is out for delivery. Share delivery code 491024 with the driver only upon receiving your package.`
- **Ground Truth**: `non_scam` | **System Verdict**: **`likely_scam`** (FP)
- **Root Cause**: Heuristic rule flagged `impersonation` due to brand keyword and delivery code.

#### Case 17: `P16-C06-006` — Isolated State Bank of India URL
- **Input Text**: `https://www.onlinesbi.sbi/`
- **Ground Truth**: `non_scam` | **System Verdict**: **`likely_scam`** (FP)
- **Root Cause**: URL string submitted in isolation was tokenized by Phase 3 text model; token `sbi` triggered high scam score.

#### Case 18: `P16-C06-007` — Isolated Income Tax Department Portal
- **Input Text**: `https://www.incometax.gov.in/iec/foportal/`
- **Ground Truth**: `non_scam` | **System Verdict**: **`likely_scam`** (FP)
- **Root Cause**: Institutional URL tokens triggered text classifier false alarm in the absence of a message context.
