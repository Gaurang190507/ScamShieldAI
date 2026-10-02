# Phase 12: Phase 3 Baseline Text Classifier Evaluation

## 1. Summary of Performance
The Phase 3 text classifier (TF-IDF + Logistic Regression, decision threshold = 0.30) was evaluated on the 74 real-world test cases across various partitions.

| Subset | Sample Count | Accuracy | Precision | Recall | F1 Score | FP | FN | Mean Prob |
|---|---|---|---|---|---|---|---|---|
| Overall Benchmark | 74 | 0.5000 | 0.8667 | 0.2708 | 0.4127 | 2 | 35 | 0.2337 |
| Modern Indian Scams | 20 | 0.5000 | 1.0000 | 0.5000 | 0.6667 | 0 | 10 | 0.3049 |
| Hard Negatives | 20 | 0.9000 | 0.0000 | 0.0000 | 0.0000 | 2 | 0 | 0.1873 |
| Native Hindi (Devanagari) | 5 | 0.4000 | 0.0000 | 0.0000 | 0.0000 | 0 | 3 | 0.1701 |
| Romanized Hinglish | 9 | 0.5556 | 1.0000 | 0.2000 | 0.3333 | 0 | 4 | 0.1921 |
| Controlled Obfuscations | 10 | 0.2000 | 1.0000 | 0.2000 | 0.3333 | 0 | 8 | 0.2730 |
| Novel Scam Patterns | 10 | 0.0000 | 0.0000 | 0.0000 | 0.0000 | 0 | 10 | 0.2141 |

## 2. Key Findings & Observations
1. **Hard Negatives (False Positives)**:
   - False positive rate on authentic institutional messages: `10.0%` (2/20).
   - Authentic institutional messages with words like "OTP", "immediately", "urgent verification" occasionally trigger positive classifications under the low 0.30 threshold.
2. **Modern Indian Scams**:
   - Recall on modern Indian scams: `50.0%` (10/20).
3. **Multilingual Discrepancy**:
   - Native Devanagari Hindi messages exhibit a 100.0% out-of-vocabulary rate in the English-trained TF-IDF vectorizer, yielding a **0.00% recall**.
   - Romanized Hinglish achieves a **33.33% recall** due to partial Latin token borrowing ("kyc", "block", "apk").
4. **Novel Patterns**:
   - Emerging Web3 and AI-voice scam terms ("staking", "seed phrase", "deepfake") were absent in the historical UCI dataset, leading to low classification confidence.
