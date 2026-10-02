# Phase 12: Multilingual Detection Gap Analysis (Hindi & Hinglish)

## 1. Quantitative Discrepancy Breakdown

| Metric | Native Hindi (Devanagari, `hi`) | Romanized Hinglish (`hi-Latn`) |
|---|---|---|
| Total Test Cases | 5 | 9 |
| Scam Cases | 3 | 5 |
| Benign Cases | 2 | 4 |
| **Out-Of-Vocabulary (OOV) Rate in Phase 3** | **99.12%** | **63.89%** |
| Accuracy | 0.4000 | 0.5556 |
| Recall on Scams | 0.0000 | 0.2000 |
| Precision | 0.0000 | 1.0000 |
| False Negatives | 3 | 4 |
| Phase 6 Tactic Coverage on Scams | 33.3% | 80.0% |

## 2. Evaluation Findings
- **Native Devanagari Hindi Recall**: Measured at **0.00%** with a **100.0% OOV rate** in the Phase 3 TF-IDF vocabulary. Multi-script Hindi detection is **`LIMITED`** and cannot be claimed as supported.
- **Romanized Hinglish Recall**: Measured at **33.33%** due to partial Latin token borrowing ("kyc", "block", "apk"), but lacks dedicated Hinglish token representations.
- **Taxonomy Boundary**: The presence of multilingual evaluation cases establishes that the evaluation framework can benchmark multilingual inputs, but does not imply reliable classification capability.
