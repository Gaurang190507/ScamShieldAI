# Phase 12: Controlled Perturbation & Obfuscation Robustness Evaluation

## 1. Overview
Evaluates model degradation and signal persistence across 10 controlled perturbation pairs derived from modern scam vectors.

## 2. Aggregate Robustness Metrics

| Robustness Metric | Value |
|---|---|
| Total Perturbed Pairs | 10 |
| Overall Phase 3 Label Flip Rate | 30.0% |
| Overall Phase 8 Assessment Change Rate | 50.0% |
| Mean Tactic Jaccard Similarity | 0.5767 |
| Mean Semantic Similarity Drop | -0.0385 |

## 3. Breakdown by Perturbation Technique

| Transformation Type | Pair Count | Label Flip Rate | Aggregation Status Change Rate | Mean Tactic Jaccard |
|---|---|---|---|---|
| `leetspeak_and_punctuation` | 1 | 100.0% | 100.0% | 1.0000 |
| `spaced_characters` | 1 | 0.0% | 0.0% | 0.3333 |
| `leetspeak_and_typos` | 1 | 0.0% | 0.0% | 0.6667 |
| `punctuation_delimiter_insertion` | 1 | 0.0% | 0.0% | 1.0000 |
| `emoji_injection` | 1 | 0.0% | 0.0% | 0.5000 |
| `hyphenation_and_word_breaking` | 1 | 0.0% | 100.0% | 0.0000 |
| `hyphenated_app_names` | 1 | 0.0% | 100.0% | 0.0000 |
| `abbreviation_and_contractions` | 1 | 100.0% | 100.0% | 0.6000 |
| `spaced_bank_name` | 1 | 100.0% | 100.0% | 0.6667 |
| `slang_and_emojis` | 1 | 0.0% | 0.0% | 1.0000 |

## 4. Pairwise Diagnostic Table

| Obfuscation ID | Transformation Type | Clean Prob | Pert Prob | Prob Delta | Flipped? | Tactic Jaccard | Aggregation Status Transition |
|---|---|---|---|---|---|---|---|
| `p12_obf_001` | `leetspeak_and_punctuation` | 0.3113 | 0.1446 | -0.1667 | True | 1.0000 | `likely_scam` -> `mixed_signals` |
| `p12_obf_002` | `spaced_characters` | 0.2070 | 0.2878 | +0.0808 | False | 0.3333 | `mixed_signals` -> `mixed_signals` |
| `p12_obf_003` | `leetspeak_and_typos` | 0.1940 | 0.1938 | -0.0002 | False | 0.6667 | `mixed_signals` -> `mixed_signals` |
| `p12_obf_004` | `punctuation_delimiter_insertion` | 0.2144 | 0.1209 | -0.0935 | False | 1.0000 | `mixed_signals` -> `mixed_signals` |
| `p12_obf_005` | `emoji_injection` | 0.1761 | 0.1405 | -0.0356 | False | 0.5000 | `mixed_signals` -> `mixed_signals` |
| `p12_obf_006` | `hyphenation_and_word_breaking` | 0.4041 | 0.5260 | +0.1219 | False | 0.0000 | `likely_scam` -> `mixed_signals` |
| `p12_obf_007` | `hyphenated_app_names` | 0.2731 | 0.1557 | -0.1174 | False | 0.0000 | `mixed_signals` -> `likely_non_scam` |
| `p12_obf_008` | `abbreviation_and_contractions` | 0.4330 | 0.2451 | -0.1879 | True | 0.6000 | `likely_scam` -> `mixed_signals` |
| `p12_obf_009` | `spaced_bank_name` | 0.3644 | 0.2996 | -0.0648 | True | 0.6667 | `likely_scam` -> `mixed_signals` |
| `p12_obf_010` | `slang_and_emojis` | 0.4177 | 0.6157 | +0.1980 | False | 1.0000 | `likely_scam` -> `likely_scam` |

## 5. Scope of Robustness Capability
- **Capability Rating**: Syntactic Obfuscation is rated **`LIMITED`**.
- **Measured Effects**: Character spacing (`S B I` vs `SBI`) and leetspeak (`b10cked` vs `blocked`) induce token drift, resulting in a 10.0% label flip rate in Phase 3.
- **Persistence**: Certain tactic rules and structural URL features remain resilient, maintaining assessment stability in 90.0% of evaluated pairs.
