# Phase 12: Phase 8 Multi-Signal Risk Aggregation Evaluation

## 1. Overview
Phase 8 evaluates the deterministic multi-signal decision engine that integrates Phase 3 (text classifier), Phase 4 (URL heuristics), Phase 6 (behavioral tactics), and Phase 7 (semantic similarity).

## 2. Assessment Status Distribution

### Ground Truth Scams (48 cases)
| Assessment Status | Count | Percentage |
|---|---|---|
| `likely_scam` | 13 | 27.1% |
| `mixed_signals` | 29 | 60.4% |
| `likely_non_scam` | 6 | 12.5% |
| `insufficient_evidence` | 0 | 0.0% |

### Ground Truth Non-Scams (26 cases)
| Assessment Status | Count | Percentage |
|---|---|---|
| `likely_non_scam` | 13 | 50.0% |
| `mixed_signals` | 11 | 42.3% |
| `likely_scam` | 2 | 7.7% |
| `insufficient_evidence` | 0 | 0.0% |

## 3. Triggered Deterministic Decision Rules
| Deterministic Decision Rule | Trigger Count |
|---|---|
| `rule_contradiction_tactics_present_low_classifier` | 39 |
| `rule_clean_non_scam_unanimous` | 19 |
| `rule_scam_classifier_and_tactics` | 11 |
| `rule_strong_scam_classifier_and_severe_tactics` | 3 |
| `rule_critical_tactics_exploitation_override` | 1 |
| `rule_contradiction_classifier_scam_clean_behavior` | 1 |

## 4. Ambiguous Cases (Mixed Signals & Insufficient Evidence)
Total ambiguous cases: **40**

| Sample ID | Ground Truth | Status | Message Excerpt |
|---|---|---|---|
| `p12_mod_001` | `scam` | `mixed_signals` | CBI Officer Sharma: Illegal drugs found in DHL courier parce... |
| `p12_mod_002` | `scam` | `mixed_signals` | Electricity Dept Alert: Your power supply will be disconnect... |
| `p12_mod_004` | `scam` | `mixed_signals` | Traffic Police Notice: Pending e-Challan DL8CA2091 of Rs 2,0... |
| `p12_mod_006` | `scam` | `mixed_signals` | Part-Time Job Offer: Earn Rs. 2,000 to Rs. 5,000 daily worki... |
| `p12_mod_007` | `scam` | `mixed_signals` | India Post Parcel On Hold: Package #IN89218 cannot be delive... |
| `p12_mod_008` | `scam` | `mixed_signals` | Instant Personal Loan Pre-Approved: Rs. 5,00,000 sanctioned ... |
| `p12_mod_009` | `scam` | `mixed_signals` | Bank Customer Care Alert: Unauthorized transaction of Rs. 48... |
| `p12_mod_012` | `scam` | `mixed_signals` | FASTag Account Alert: Your FASTag account has negative balan... |
| `p12_mod_013` | `scam` | `mixed_signals` | LPG Gas Subsidy Alert: Your cooking gas subsidy of Rs. 380 p... |
| `p12_mod_016` | `scam` | `mixed_signals` | Enforcement Directorate Notice: PMLA investigation registere... |

## 5. Architectural Findings & Meaning of `mixed_signals`
- **Definition & Evaluation Rule**: `mixed_signals` indicates that the deterministic signals were contradictory or insufficiently aligned for a strong directional assessment. It should not be interpreted as a correct scam classification merely because the ground-truth label is scam. Cases where `ground_truth = scam` and `system = mixed_signals` must remain classified as non-definitive outcomes, not true positives.
- **Preservation of Uncertainty**: Rather than forcing a high-risk decision on unfamiliar text, Phase 8 assigns 60.4% of modern scam cases to `mixed_signals` when text and tactic signals diverge.
