# ScamShield AI — Phase 13 Hard Negative Discrimination Report

**Evaluation Date**: October 2, 2026  
**Objective**: Verify that high-urgency legitimate communications are NOT misclassified as scams.  
**Core Invariant**:
```text
urgency ≠ scam
OTP ≠ scam
payment ≠ scam
link ≠ scam
authority ≠ scam
```

---

## 1. Measured Performance on Expanded Hard-Negative Benchmark (25 Legitimate Cases)

| Model | Total Benign Samples | Correctly Rejected (TN) | False Alarms (FP) | False Positive Rate (FP / 25) |
| :--- | :--- | :--- | :--- | :--- |
| **Model A (Baseline)** | 25 | 24 | 1 | **4.0% (1/25)** |
| **Model B (Char n-gram)** | 25 | 24 | 1 | **4.0% (1/25)** |
| **Model C (Semantic Dense)** | 25 | 12 | 13 | **52.0% (13/25)** |
| **Model D (Hybrid Fusion)** | 25 | 17 | 8 | **32.0% (8/25)** |

---

## 2. Qualitative Discrimination Analysis across Benign Categories

1. **Bank Transaction & Login OTPs**:
   - Model A and Model B successfully discriminate authentic bank OTPs (`"Your OTP for HDFC NetBanking login is 839201. Do not share..."`). Both models recognize that warning the recipient *not* to share OTP indicates legitimate transactional context.
   - Model C flags several OTPs as scams because dense embeddings associate "OTP" and "bank" with smishing clusters.
2. **Flight Rescheduling & Urgent Service Alerts**:
   - Indigo airline flight delay alert containing urgent reschedule notices was correctly classified as non-scam by Model B.
3. **Government Tax Deadlines & Traffic Challans**:
   - Authentic notices from Income Tax Department and Parivahan Traffic Police were correctly classified as legitimate by Model B.
4. **Takeaway**:
   - Model B preserves the lowest observed False Positive Rate (**4.0%, 1/25**) on authentic urgent messages, meeting the hard-negative integrity requirement.
