# ScamShield AI — Phase 3 Baseline Evaluation Report

**Model:** Text-only TF-IDF + Logistic Regression  
**Dataset:** UCI SMS Spam Collection (`data/processed/preprocessed/uci_sms_spam.jsonl`)  
**Evaluation Mode:** Leakage-safe Group Partitioning with Duplicate Text Clustering (70% Train / 15% Val / 15% Test)  

---

## 1. Dataset Partitioning & Leakage Safeguards

All campaign clusters and normalized duplicate text clusters were partitioned with zero pattern group overlap and zero duplicate text overlap:

| Split | Count | Proportion | Scam Samples | Non-Scam Samples | Scam % |
| :--- | :---: | :---: | :---: | :---: | :---: |
| **Train** | 3881 | 69.63% | 520 | 3361 | 13.4% |
| **Validation** | 837 | 15.02% | 104 | 733 | 12.43% |
| **Test** | 856 | 15.36% | 123 | 733 | 14.37% |
| **Total** | **5574** | **100.0%** | **747** | **4827** | **13.4%** |

*Leakage Verification:* Splits are verified 100% leakage-free across pattern groups.  
*Duplicate Text Isolation:* 0 (verified zero exact or normalized duplicate text overlap across splits)  
*Unique Split Clusters:* 5159 clusters across 5,574 samples.

---

## 2. Test Set Performance

### Selected Operating Threshold (0.30 — Tuned on Validation F1)
- **Accuracy**: `98.25%`
- **ROC-AUC**: `0.9979`
- **Scam Precision**: `95.76%`
- **Scam Recall**: `91.87%`
- **Scam F1-Score**: `93.78%`
- **Macro Avg F1**: `96.38%`
- **Weighted Avg F1**: `98.23%`

**Confusion Matrix (Threshold 0.30):**
- True Negatives (TN): `728`
- False Positives (FP): `5`
- False Negatives (FN): `10`
- True Positives (TP): `113`

### Default Threshold (0.50 Reference)
- **Accuracy**: `96.38%`
- **ROC-AUC**: `0.9979`
- **Scam Precision**: `100.00%`
- **Scam Recall**: `74.80%`
- **Scam F1-Score**: `85.58%`

*Threshold Analysis Note:* At 0.50, the model achieves 100.00% precision but suffers lower recall (74.80%), missing 31 spam/scam messages due to dataset class imbalance (86.6% non-scam vs 13.4% scam). Lowering the decision threshold to 0.30 on the validation set reduces false negatives to 10 while maintaining 95.76% precision.

---

## 3. Error Analysis Summary

Total Test Errors at Threshold 0.30: **15** / 856 samples (1.75% error rate).

### False Positives (Actual: Non-Scam → Predicted: Scam) [5 Cases]
Legitimate messages containing commercial or call cues that triggered high spam token weights:
- **[uci_sms_2380]** (prob: `0.3764`): "Hi, Mobile no.  &lt;#&gt;  has added you in their contact list on www.fullonsms.com It s a great place to send free sms to people For more visit fullonsms.com"
- **[uci_sms_3365]** (prob: `0.3852`): "Can... I'm free..."
- **[uci_sms_4305]** (prob: `0.3308`): "Yup i'm free..."
- **[uci_sms_4703]** (prob: `0.3271`): "I liked the new mobile"
- **[uci_sms_4774]** (prob: `0.3764`): "Hi, Mobile no.  &lt;#&gt;  has added you in their contact list on www.fullonsms.com It s a great place to send free sms to people For more visit fullonsms.com"

### False Negatives (Actual: Scam → Predicted: Non-Scam) [10 Cases]
Spam messages that evaded word-level TF-IDF features due to conversational phrasing, news reporting format, or typos:
- **[uci_sms_1270]** (prob: `0.1714`): "Can U get 2 phone NOW? I wanna chat 2 set up meet Call me NOW on 09096102316 U can cum here 2moro Luv JANE xx Calls£1/minmoremobsEMSPOBox45PO139WA"
- **[uci_sms_1675]** (prob: `0.2623`): "Monthly password for wap. mobsi.com is 391784. Use your wap phone not PC."
- **[uci_sms_2353]** (prob: `0.1963`): "Download as many ringtones as u like no restrictions, 1000s 2 choose. U can even send 2 yr buddys. Txt Sir to 80082 £3"
- **[uci_sms_2916]** (prob: `0.2028`): "Sorry! U can not unsubscribe yet. THE MOB offer package has a min term of 54 weeks> pls resubmit request after expiry. Reply THEMOB HELP 4 more info"
- **[uci_sms_3502]** (prob: `0.2295`): "Dorothy@kiefer.com (Bank of Granite issues Strong-Buy) EXPLOSIVE PICK FOR OUR MEMBERS *****UP OVER 300% *********** Nasdaq Symbol CDGT That is a $5.00 per.."
- **[uci_sms_3575]** (prob: `0.2813`): "You won't believe it but it's true. It's Incredible Txts! Reply G now to learn truly amazing things that will blow your mind. From O2FWD only 18p/txt"
- **[uci_sms_4822]** (prob: `0.2091`): "Check Out Choose Your Babe Videos @ sms.shsex.netUN fgkslpoPW fgkslpo"

---

## 4. Key Takeaways & Limitations

1. **Text-Only Baseline**: Relies purely on lexical TF-IDF n-grams without multi-label tactical indicators, URL structural heuristics, or semantic representations.
2. **Historical Dataset**: The UCI SMS Spam Collection reflects 2011 UK/Singapore carrier SMS spam. It lacks modern Indian vectors (digital arrest, APK sideloading, UPI fraud).
3. **Spam vs. Scam**: Many historical spam samples are commercial ringtone or adult chat advertisements rather than fraudulent identity theft attacks.
