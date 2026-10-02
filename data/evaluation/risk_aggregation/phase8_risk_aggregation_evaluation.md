# ScamShield AI — Phase 8: Multi-Signal Risk Aggregation & Forensic Audit Evaluation Report

## 1. Executive Summary

This empirical report documents the formal evaluation of the **Phase 8 Multi-Signal Risk Aggregator and Forensic Audit Engine** across the held-out canonical **TEST split (856 samples)** and synthetic benchmark edge scenarios.

> **Dataset Limitation Notice**:
> "The UCI SMS Spam Collection was originally annotated as spam/ham. ScamShield normalizes these labels to scam/non_scam for the benchmark classification task. These labels are not equivalent to verified real-world scam provenance."

### Core Evaluation Findings
1. **Zero Pseudo-Probabilities**: All case verdicts are derived from explicit, deterministic logical rules combining observable signals (TF-IDF classifier, URL syntax, behavioral tactic spans, semantic vector proximity).
2. **Transparent Contradiction Resolution**: Rather than forcing a binary classification when signals disagree, the engine categorizes divergent inputs as `mixed_signals` (68 samples, 7.94% of test split), highlighting conflicting evidence and cautionary flags.
3. **Contradiction Routing in Benchmark Scams**: Contradiction routing assigned 51 of 123 scam-labeled benchmark samples (41.46%) to `mixed_signals` rather than `likely_scam`. This reflects the deterministic aggregation rules and demonstrates that the system does not force every scam-labeled benchmark sample into a binary scam verdict.
   - *Deterministic Audit of the 51 Mixed Scam Benchmark Cases*:
     - **URL Evidence**: 0 with URL evidence, 51 without URL evidence
     - **Tactic Evidence**: 0 with tactic evidence, 51 without tactic evidence
     - **Classifier Support ($P_{\text{cls}} \ge 0.30$)**: 51 with classifier support, 0 without classifier support
     - **Semantic Novelty ($S_{\text{nov}} \ge 0.50$)**: 7 with semantic novelty, 44 without semantic novelty
     - *Triggered Rule*: All 51 cases triggered `rule_contradiction_classifier_scam_clean_behavior`.
4. **Behavior on Non-Scam Benchmark Samples**: Among the 733 non-scam-labeled benchmark samples, 714 (97.41%) were assigned `likely_non_scam`, 17 (2.32%) were assigned `mixed_signals`, and 2 (0.27%) were assigned `likely_scam`. These figures describe behavior on the current benchmark and should not be interpreted as a measured real-world false-positive rate.
5. **Strict Offline Audit Compliance**: Every evaluated case generated an immutable `AuditObject` certifying `network_access: false`, `external_lookup: false`, and `phase5_used: false`.

---

## 2. Test Split Quantitative Evaluation (N = 856)

### 2.1 Overall Assessment Distribution

| Assessment Status | Count | Percentage | Primary Meaning |
| :--- | :--- | :--- | :--- |
| **likely_non_scam** | 724 | 84.58% | Clean content; no tactics, no URL threats, text score below threshold |
| **likely_scam** | 64 | 7.48% | Corroborated scam evidence across classifier and tactics/URLs |
| **mixed_signals** | 68 | 7.94% | Conflicting signals requiring human triage / corroborating evidence |
| **insufficient_evidence** | 0 | 0.00% | Blank or sub-minimal text input |
| **Total** | **856** | **100.00%** | Held-out test split |

### 2.2 Status Breakdown by Ground Truth Label

| Ground Truth Label | Total | likely_scam | mixed_signals | likely_non_scam | insufficient |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **Scam** | 123 | 62 (50.4%) | 51 (41.5%) | 10 (8.1%) | 0 (0.0%) |
| **Non-Scam** | 733 | 2 (0.3%) | 17 (2.3%) | 714 (97.4%) | 0 (0.0%) |

### 2.3 Decision Rule Trigger Frequency

| Triggered Decision Rule | Count | Percentage | Rule Description |
| :--- | :--- | :--- | :--- |
| `rule_clean_non_scam_unanimous` | 724 | 84.58% | Deterministic logic rule |
| `rule_contradiction_classifier_scam_clean_behavior` | 54 | 6.31% | Deterministic logic rule |
| `rule_scam_classifier_and_tactics` | 51 | 5.96% | Deterministic logic rule |
| `rule_contradiction_tactics_present_low_classifier` | 14 | 1.64% | Deterministic logic rule |
| `rule_strong_scam_classifier_and_severe_tactics` | 13 | 1.52% | Deterministic logic rule |

### 2.4 Evidence Level & Signal Consistency

| Metric Dimension | Level / Category | Count | Percentage |
| :--- | :--- | :--- | :--- |
| **Evidence Level** | High | 13 | 1.52% |
| | Moderate | 119 | 13.90% |
| | Low | 724 | 84.58% |
| **Signal Consistency** | Strong Agreement | 735 | 85.86% |
| | Moderate Agreement | 53 | 6.19% |
| | Mixed (Disagreement) | 68 | 7.94% |
| | Insufficient | 0 | 0.00% |

### 2.5 Evidence Volume & Audit Statistics
- **Mean Evidence Items per Case**: 3.13 (min: 3, max: 7)
- **Mean Contradicting Signals per Case**: 1.80
- **Inference Latency**: 28.99 ms per sample (including embedding inference + NumPy nearest-neighbor search)
- **Zero External Network / DNS Access**: 100% verified across all 856 cases.

---

## 3. Forensic Case Studies

### 3.1 Case Study: Strong Scam (Corroborated)
- **Sample ID**: `uci_sms_0012`
- **True Label**: `scam`
- **Message Text**:
  > "SIX chances to win CASH! From 100 to 20,000 pounds txt> CSH11 and send to 87575. Cost 150p/day, 6days, 16+ TsandCs apply Reply HL 4 info"
- **Assessment Verdict**: `likely_scam` (Evidence Level: `high`, Consistency: `strong_agreement`)
- **Triggered Decision Rule**: `rule_strong_scam_classifier_and_severe_tactics`
- **Signals**:
  - Classifier Score: 0.887 (Threshold: 0.3)
  - Tactics Detected: ['payment_request', 'reward_claim'] (Count: 2)
  - URL Max Risk: 0.0 (Count: 0)
  - Semantic Similarity: 0.6492 (Status: `moderately_novel`)
- **Explanation**:
  - *Summary*: Assessment: LIKELY SCAM (HIGH evidence level). Multiple corroborating signals indicate deceptive or manipulative intent.
  - *Reasons*:
    - Statistical text classifier indicates scam pattern (estimated score: 0.8870, threshold: 0.30).
    - Detected 2 behavioral tactic(s): payment_request, reward_claim.
    - Contains 1 high-severity exploitation tactic(s) (payment_request).
    - Semantic proximity to training reference corpus: top-1 similarity 0.6492 (moderately_novel).

### 3.2 Case Study: Unanimous Legitimate Non-Scam
- **Sample ID**: `uci_sms_0017`
- **True Label**: `non_scam`
- **Message Text**:
  > "Oh k...i'm watching here:)"
- **Assessment Verdict**: `likely_non_scam` (Evidence Level: `low`, Consistency: `strong_agreement`)
- **Triggered Decision Rule**: `rule_clean_non_scam_unanimous`
- **Signals**:
  - Classifier Score: 0.0355 (Threshold: 0.3)
  - Tactics Detected: [] (Count: 0)
  - URL Max Risk: 0.0 (Count: 0)
  - Semantic Similarity: 0.4629 (Status: `potentially_novel`)
- **Explanation**:
  - *Summary*: Assessment: LIKELY NON-SCAM. The message does not exhibit manipulative tactics, the text classifier is below threshold, and no URL structural threats were identified.
  - *Reasons*:
    - Statistical text classifier indicates non-scam pattern (estimated score: 0.0355, threshold: 0.30).
    - Zero manipulative behavioral tactics detected in message text.
    - Semantic proximity to training reference corpus: top-1 similarity 0.4629 (potentially_novel).
  - *Cautions*:
    ! High semantic novelty score (0.5371): message diverges from the reference training corpus. Novelty indicates uncataloged vocabulary or pattern structure, not definitive fraud.

### 3.3 Case Study: Contradiction: Lexical Alert with Clean Behavior
- **Sample ID**: `uci_sms_0057`
- **True Label**: `scam`
- **Message Text**:
  > "Congrats! 1 year special cinema pass for 2 is yours. call 09061209465 now! C Suprman V, Matrix3, StarWars3, etc all 4 FREE! bx420-ip4-5we. 150pm. Dont miss out!"
- **Assessment Verdict**: `mixed_signals` (Evidence Level: `moderate`, Consistency: `mixed`)
- **Triggered Decision Rule**: `rule_contradiction_classifier_scam_clean_behavior`
- **Signals**:
  - Classifier Score: 0.3678 (Threshold: 0.3)
  - Tactics Detected: [] (Count: 0)
  - URL Max Risk: 0.0 (Count: 0)
  - Semantic Similarity: 0.4269 (Status: `potentially_novel`)
- **Explanation**:
  - *Summary*: Assessment: MIXED SIGNALS. Independent signals contradict each other. Requires careful inspection of specific evidence findings.
  - *Reasons*:
    - Statistical text classifier indicates scam pattern (estimated score: 0.3678, threshold: 0.30).
    - Zero manipulative behavioral tactics detected in message text.
    - Semantic proximity to training reference corpus: top-1 similarity 0.4269 (potentially_novel).
  - *Cautions*:
    ! Upstream signals actively disagree. Manual investigation or corroborating evidence is recommended before acting.
    ! The text classifier assigned a high scam score, but no explicit deceptive tactics or URL anomalies were confirmed.
    ! High semantic novelty score (0.5731): message diverges from the reference training corpus. Novelty indicates uncataloged vocabulary or pattern structure, not definitive fraud.

### 3.4 Case Study: Contradiction: Subtle Tactic with Low Text Score
- **Sample ID**: `uci_sms_0569`
- **True Label**: `non_scam`
- **Message Text**:
  > "So anyways, you can just go to your gym or whatever, my love *smiles* I hope your ok and having a good day babe ... I miss you so much already"
- **Assessment Verdict**: `mixed_signals` (Evidence Level: `moderate`, Consistency: `mixed`)
- **Triggered Decision Rule**: `rule_contradiction_tactics_present_low_classifier`
- **Signals**:
  - Classifier Score: 0.04 (Threshold: 0.3)
  - Tactics Detected: ['romance_manipulation'] (Count: 1)
  - URL Max Risk: 0.0 (Count: 0)
  - Semantic Similarity: 0.6311 (Status: `moderately_novel`)
- **Explanation**:
  - *Summary*: Assessment: MIXED SIGNALS. Independent signals contradict each other. Requires careful inspection of specific evidence findings.
  - *Reasons*:
    - Statistical text classifier indicates non-scam pattern (estimated score: 0.0400, threshold: 0.30).
    - Detected 1 behavioral tactic(s): romance_manipulation.
    - Semantic proximity to training reference corpus: top-1 similarity 0.6311 (moderately_novel).
  - *Cautions*:
    ! Upstream signals actively disagree. Manual investigation or corroborating evidence is recommended before acting.

## 4. Key Architectural Insights & Verification Conclusions

1. **Why Linear Score Averaging Fails**:
   In naive ensemble systems, when a classifier outputs $0.95$ (scam) and URL analysis outputs $0.00$ (clean), linear averaging computes $0.475$, classifying the message as borderline or low-risk without explaining why. Phase 8 explicitly recognizes this as a **contradiction** (`mixed_signals`), exposing the exact divergence to investigators.
2. **Behavioral Grounding and Contradiction Routing**:
   Lexical classifiers often assign high scores to messages containing marketing words like "free", "offer", or "win". By requiring corroborating behavioral tactics (urgency, impersonation, credential harvesting) or URL threats for a `likely_scam` verdict, Phase 8 routes cases lacking behavioral corroboration to `mixed_signals` rather than declaring an uncorroborated scam verdict. Among the 733 non-scam-labeled benchmark samples, 714 (97.41%) were assigned `likely_non_scam`, 17 (2.32%) were assigned `mixed_signals`, and 2 (0.27%) were assigned `likely_scam`. These figures describe behavior on the current benchmark and should not be interpreted as a measured real-world false-positive rate.
3. **Audit of Mixed Scam Benchmark Cases**:
   Among the 51 scam-labeled benchmark samples assigned `mixed_signals`:
   - 0 had URL evidence (51 without URL evidence)
   - 0 had tactic evidence (51 without tactic evidence)
   - 51 had classifier support (0 without classifier support)
   - 7 had semantic novelty (44 without semantic novelty)
   All 51 cases triggered `rule_contradiction_classifier_scam_clean_behavior`.
4. **Semantic Novelty Decoupled from Guilt**:
   Unusual vocabulary (such as technical jargon or uncommon dialects) scores high on semantic novelty ($> 0.60$). Phase 8 explicitly cautions that novelty reflects distance from the training corpus, ensuring benign novel messages are never penalized as scams based on novelty alone.
5. **Phase 5 Frozen**:
   The audit log confirms `phase5_used: false` on every transaction, preserving Phase 5 as a standalone research artifact and preventing double-counting.
