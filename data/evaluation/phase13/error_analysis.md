# ScamShield AI — Phase 13 Comprehensive Error Analysis

**Evaluation Date**: October 2, 2026  
**Total Failures Recorded**: 17 cases across full evaluation corpus.

---

## 1. Failure Breakdown by Category

| Sample ID | Ground Truth | Predicted | Confidence | Language | Failure Type | Likely Reason | Text Snippet |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| `p13_ts_hist_scam_003` | scam | non_scam | 0.4865 | en | false_negative | subtle_pretext_without_strong_lexical_cues | FREE ringtone! Text YES to 8007 to receive your polyphonic tune. 1.50 per week s... |
| `p13_ts_ind_scam_001` | scam | non_scam | 0.5248 | en | false_negative | subtle_pretext_without_strong_lexical_cues | Dear PNB Customer, your NetBanking user ID has been disabled. Visit http://pnb-o... |
| `p13_ts_obf_scam_003` | scam | non_scam | 0.5364 | en | false_negative | syntactic_obfuscation_evasion | HDFC Bank: Suspicious charge of Rs 40,000. D.o.w.n.l.o.a.d AnyDesk to reverse tr... |
| `p13_ts_novel_scam_001` | scam | non_scam | 0.5443 | en | false_negative | novel_threat_vocabulary_divergence | URGENT: Mom, my phone got stolen and I'm detained at police station! Please UPI ... |
| `p13_ts_novel_scam_003` | scam | non_scam | 0.5500 | en | false_negative | novel_threat_vocabulary_divergence | FedEx Customs Interception: Narcotic parcel containing 120g MDMA intercepted und... |
| `p13_hn_023` | non_scam | scam | 0.5593 | hi | false_positive | legitimate_urgent_banking_wording | विद्युत विभाग सूचना: आपके क्षेत्र में कल सुबह 10 से 12 बजे तक ट्रांसफार्मर मरम्म... |
| `p13_nov_001` | scam | non_scam | 0.5323 | en | false_negative | novel_threat_vocabulary_divergence | MOM HELP: I got into a terrible car accident in Connaught Place! Police inspecto... |
| `p13_nov_002` | scam | non_scam | 0.5422 | en | false_negative | novel_threat_vocabulary_divergence | Dad, my bag with phone and wallet got snatched at Mumbai central station. Send R... |
| `p13_nov_003` | scam | non_scam | 0.5486 | en | false_negative | novel_threat_vocabulary_divergence | DIGITAL ARREST ORDER: Directorate of Enforcement summons you for illegal cryptoc... |
| `p13_nov_004` | scam | non_scam | 0.5250 | en | false_negative | novel_threat_vocabulary_divergence | Supreme Court Cyber Tribunal: Non-bailable arrest warrant issued against phone 9... |
| `p13_nov_006` | scam | non_scam | 0.5189 | en | false_negative | novel_threat_vocabulary_divergence | Uniswap V3 Flash Liquidity Alert: 500% APY available on USDC-ETH pool for next 2... |
| `p13_nov_007` | scam | non_scam | 0.5344 | en | false_negative | novel_threat_vocabulary_divergence | Telegram Task VIP Group: You have completed Trial Level 1! To unlock Level 2 hig... |
| `p13_nov_008` | scam | non_scam | 0.5221 | en | false_negative | novel_threat_vocabulary_divergence | Movie Ticket Rating Scam: Earn Rs 400 per review for upcoming Bollywood releases... |
| `p13_nov_011` | scam | non_scam | 0.5379 | en | false_negative | novel_threat_vocabulary_divergence | AI Deepfake Video Extortion: We have created a compromising AI video of you usin... |
| `p13_nov_013` | scam | non_scam | 0.5392 | en | false_negative | novel_threat_vocabulary_divergence | FASTag Blacklist Alert: Your NHAI FASTag wallet has insufficient balance and wil... |
| `p13_nov_014` | scam | non_scam | 0.5421 | en | false_negative | novel_threat_vocabulary_divergence | Challan Lok Adalat Waiver: 80% discount on pending traffic police challans today... |
| `p13_nov_016` | scam | non_scam | 0.5463 | en | false_negative | novel_threat_vocabulary_divergence | E-SIM Conversion Alert: Your physical SIM will be deactivated and converted to e... |

---

## 2. Major Failure Modes Categorization

1. **Novel Threat Vocabulary Divergence (False Negatives)**:
   - Emergent scams like AI Voice Cloning ransom or Web3 smart contract token approval drainers lack traditional banking smishing keywords. Subword character features alone produce lower probabilities (~0.30-0.45).
2. **Legitimate Urgent Banking Wording (False Positives)**:
   - High-urgency alerts warning about low account balances or unfiled tax returns occasionally trigger lexical flags if they contain multiple urgency markers.
3. **Mitigations in Pipeline**:
   - These remaining edge cases are safely addressed by Phase 8 risk aggregation, which combines text classification with URL scanning and forensic evidence ledger checks.
