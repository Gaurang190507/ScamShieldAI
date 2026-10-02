# Phase 12: Comprehensive Error Analysis & Failure Taxonomy

## 1. Executive Summary
This report catalogs the failure modes observed during Phase 12 evaluation across False Positives, False Negatives, and Ambiguous predictions.

- Total False Positives Cataloged: **2**
- Total False Negatives Cataloged: **35**

## 2. False Positives (Benign Messages Flagged as Scam)

| Sample ID | Subcategory | Model Pred | Model Prob | Agg Status | Tactics Detected | Message Excerpt |
|---|---|---|---|---|---|---|
| `p12_hneg_017` | `healthcare_report` | `scam` | 0.3631 | `likely_scam` | `link_redirection` | Dr Lal PathLabs: Your diagnostic blood test report for Booking ID BLR91820 is ready. Download report securely from our p |
| `p12_hneg_020` | `card_statement` | `scam` | 0.3201 | `likely_scam` | `impersonation` | Kotak Credit Card Statement: e-Statement for Card ending 8192 for Sep-2026 has been sent to your email. Password to open |

### Root Cause Analysis for False Positives:
1. **Urgency in Legitimate Institutional Workflows**: Banks, utilities, and logistics services legitimately use high-urgency language ("expires in 5 minutes", "immediate action required", "do not share OTP").
2. **Low Operating Threshold (0.30)**: The Phase 3 classifier threshold of 0.30 favors recall, leading to occasional false positives on urgent institutional notifications.

## 3. False Negatives (Scams Missed by Model)

| Sample ID | Subcategory | Model Pred | Model Prob | Agg Status | Tactics Detected | Message Excerpt |
|---|---|---|---|---|---|---|
| `p12_mod_001` | `digital_arrest` | `non_scam` | 0.1782 | `mixed_signals` | `impersonation, urgency` | CBI Officer Sharma: Illegal drugs found in DHL courier parcel under your Aadhaar. Connect on Skype immediately for digit |
| `p12_mod_002` | `electricity_bill` | `non_scam` | 0.2070 | `mixed_signals` | `payment_request, impersonation, urgency` | Electricity Dept Alert: Your power supply will be disconnected tonight at 9:30 PM due to unpaid bill of Rs 1,420. Call e |
| `p12_mod_004` | `e_challan` | `non_scam` | 0.2144 | `mixed_signals` | `link_redirection, threat, urgency` | Traffic Police Notice: Pending e-Challan DL8CA2091 of Rs 2,000 for speeding. Pay fine within 24 hours to avoid court sum |
| `p12_mod_006` | `task_scam` | `non_scam` | 0.1761 | `mixed_signals` | `impersonation, job_offer` | Part-Time Job Offer: Earn Rs. 2,000 to Rs. 5,000 daily working from home just by liking YouTube videos and rating hotels |
| `p12_mod_007` | `delivery_fraud` | `non_scam` | 0.1940 | `mixed_signals` | `payment_request, impersonation, link_redirection` | India Post Parcel On Hold: Package #IN89218 cannot be delivered due to incomplete delivery address. Pay Rs. 25 re-delive |
| `p12_mod_008` | `loan_scam` | `non_scam` | 0.1875 | `mixed_signals` | `payment_request` | Instant Personal Loan Pre-Approved: Rs. 5,00,000 sanctioned under PM Mudra Yojana at 2% interest. Zero cibil required. S |
| `p12_mod_009` | `remote_access` | `non_scam` | 0.2731 | `mixed_signals` | `remote_access_request, urgency` | Bank Customer Care Alert: Unauthorized transaction of Rs. 48,900 detected on your credit card. To cancel this transactio |
| `p12_mod_012` | `toll_fastag` | `non_scam` | 0.2893 | `mixed_signals` | `link_redirection, urgency` | FASTag Account Alert: Your FASTag account has negative balance and will be blacklisted across all highway toll gates. Re |
| `p12_mod_013` | `subsidy_fraud` | `non_scam` | 0.2572 | `mixed_signals` | `impersonation, link_redirection, urgency` | LPG Gas Subsidy Alert: Your cooking gas subsidy of Rs. 380 per cylinder has been stopped. Link your bank passbook and Aa |
| `p12_mod_016` | `digital_arrest` | `non_scam` | 0.1907 | `mixed_signals` | `impersonation, urgency` | Enforcement Directorate Notice: PMLA investigation registered against your PAN. Failure to submit verified affidavit wit |
| `p12_ml_001` | `kyc_suspension` | `non_scam` | 0.2667 | `mixed_signals` | `impersonation, link_redirection` | प्रिय ग्राहक, आपका SBI बैंक खाता आज रात 9:30 बजे ब्लॉक कर दिया जाएगा। तुरंत अपना पैन कार्ड अपडेट करें: http://192.168.1. |
| `p12_ml_002` | `electricity_bill` | `non_scam` | 0.0837 | `likely_non_scam` | `none` | बिजली विभाग सूचना: आपके घर की बिजली आज रात 9 बजे काट दी जाएगी क्योंकि पिछले माह का बिल बकाया है। तुरंत इस नंबर 987654321 |
| `p12_ml_003` | `loan_scam` | `non_scam` | 0.1758 | `likely_non_scam` | `none` | बधाई हो! आपको प्रधानमंत्री मुद्रा योजना के तहत 5,00,000 रुपये का ऋण स्वीकृत हुआ है। पंजीकरण शुल्क 1,999 रुपये जमा करने ह |
| `p12_ml_006` | `kyc_suspension` | `non_scam` | 0.1977 | `mixed_signals` | `impersonation, link_redirection` | Aapka SBI account aaj block ho jayega. Turant apna PAN update karein at http://sbi-kyc-update.com/verify warna account p |
| `p12_ml_007` | `electricity_bill` | `non_scam` | 0.2105 | `mixed_signals` | `impersonation, urgency` | Bijli vibhag urgent notice: Aapka electricity bill pending hai. Aaj raat 9 baje light cut kar di jayegi. Cutoff se bachn |
| `p12_ml_008` | `task_scam` | `non_scam` | 0.1521 | `likely_non_scam` | `none` | Part time work from home opportunity! Daily 2000 se 5000 kamaye YouTube videos like karke. Contact HR manager on Telegra |
| `p12_ml_009` | `digital_arrest` | `non_scam` | 0.1495 | `mixed_signals` | `impersonation` | CBI Police Officer: Aapke naam par DHL parcel me charas mila hai. Digital arrest se bachne ke liye turant Skype call par |
| `p12_nov_001` | `web3_novel` | `non_scam` | 0.2905 | `mixed_signals` | `link_redirection, urgency` | Quantum compute nodes have allocated cloud token credits. Sync node wallet immediately to harvest staking yields: http:/ |
| `p12_nov_002` | `ai_voice_emergency` | `non_scam` | 0.0986 | `mixed_signals` | `payment_request, urgency` | AI Voice Clone Emergency: Dad, I had a terrible car accident in Delhi and my phone is broken. Police are arresting me. P |
| `p12_nov_003` | `web3_novel` | `non_scam` | 0.1835 | `likely_scam` | `credential_request, link_redirection` | Decentralized Web3 Airdrop: Claim 1,500 ARB ecosystem governance tokens before liquidity snapshot. Connect cold wallet s |
| `p12_nov_004` | `web3_novel` | `non_scam` | 0.2311 | `likely_non_scam` | `none` | Autonomous Agent Protocol: Your API compute container exceeded memory allocation. Deposit 0.05 ETH gas fee to contract 0 |
| `p12_nov_005` | `digital_arrest` | `non_scam` | 0.1935 | `mixed_signals` | `impersonation, link_redirection` | Deepfake Video Verification: High Court Registry summons requires 3D facial biometric scan via remote browser sandbox at |
| `p12_nov_006` | `task_scam` | `non_scam` | 0.1888 | `mixed_signals` | `link_redirection` | Neural Network Node Validator: Allocate 8GB VRAM compute share to validate decentralized LLM tokens. Earn daily yield of |
| `p12_nov_007` | `telecom_fraud` | `non_scam` | 0.2325 | `mixed_signals` | `link_redirection` | Satellite Mesh Network: Your Low Earth Orbit bandwidth allocation is exhausted. Tap to bridge satellite credentials and  |
| `p12_nov_008` | `web3_novel` | `non_scam` | 0.2519 | `mixed_signals` | `link_redirection` | Cross-Chain Bridge Staking: Migrate smart contract liquidity to Layer-2 rollup network. Instant 18% APY boost. Approve t |
| `p12_nov_009` | `telecom_fraud` | `non_scam` | 0.2229 | `mixed_signals` | `urgency` | E-SIM Cloud Activation: Remote eSIM profile profile-v918 installed successfully. To cancel unauthorized transfer to fore |
| `p12_nov_010` | `web3_novel` | `non_scam` | 0.2474 | `likely_non_scam` | `none` | Decentralized Storage Payout: Filecoin storage node pinning reward of 420 FIL ready for release. Submit private mnemonic |
| `p12_obf_001` | `kyc_suspension` | `non_scam` | 0.1446 | `mixed_signals` | `impersonation, link_redirection, urgency` | URGENT!!! Y0ur SB1 b@nk acc0unt susp3nded t0day! Plz v3r1fy PAN imm3di@tely at http://sbi-kyc-verify-portal.in |
| `p12_obf_002` | `electricity_bill` | `non_scam` | 0.2878 | `mixed_signals` | `urgency` | E l e c t r i c i t y   D e p t: P o w e r   c u t o f f   t o n i g h t! Call 9876543210 urgently to clear pending bala |
| `p12_obf_003` | `delivery_fraud` | `non_scam` | 0.1938 | `mixed_signals` | `payment_request, link_redirection` | 1ndia P0st: P@ckage #IN89218 is 0n h0ld. Pay Rs 25 del1very fee at http://indiapost-redelivery.top or parcell will be re |
| `p12_obf_004` | `e_challan` | `non_scam` | 0.1209 | `mixed_signals` | `link_redirection, threat, urgency` | TRAFFIC POLICE NOTICE :::: Pending challan of Rs 2000. Pay fine immediately before court summons at http://192.168.1.100 |
| `p12_obf_005` | `task_scam` | `non_scam` | 0.1405 | `mixed_signals` | `job_offer` | PART-TIME JOB OFFER 💰💰 Earn Rs 2000-5000 daily liking videos ⭐ Join HR on Telegram @earnmoneytask99 🚀🚀 |
| `p12_obf_007` | `remote_access` | `non_scam` | 0.1557 | `likely_non_scam` | `none` | BANK ALERT: Un-authorized transaction detected! Plz install Any-Desk or Quick-Support app to reverse payment. |
| `p12_obf_008` | `tax_refund` | `non_scam` | 0.2451 | `mixed_signals` | `link_redirection, urgency, refund_claim` | INCOME TAX ALERT :::: Refund of Rs 18450 waiting. Confirm acct details within 24hr: http://incometax-refundportal.click/ |
| `p12_obf_009` | `reward_points` | `non_scam` | 0.2996 | `mixed_signals` | `impersonation, link_redirection, urgency` | H D F C   B a n k: 9450 points expirin today! Redeem at http://hdfc-reward-redeem.com/cash immediately. |

### Root Cause Analysis for False Negatives:
1. **Native Devanagari Hindi Text**: Completely absent from the historical training split, yielding a 100% out-of-vocabulary rate.
2. **Novel Web3 & AI Vectors**: Jargon such as "validator node", "smart contract", "deepfake" lacks statistical weight in the 2012 UCI vocabulary.
3. **Subtle Conversational Pretexts**: Modern scammers frequently begin with low-pressure pretext messages without immediate payment or credential requests.
