# ScamShield AI — Phase 13 Tactic-Aware Learning Experiment

**Evaluation Date**: October 2, 2026  
**Objective**: Investigate whether augmenting text models with Phase 6 behavioral tactics and Phase 4 URL heuristics improves generalization.

---

## 1. Ablation Comparison on Consolidated Test Set (31 Cases)

| Representation Configuration | Accuracy | Precision | Recall (TP / 23) | F1 Score | Hard-Negative FPR (FP / 25) |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **Text Only (Model B)** | 83.87% (26/31) | 100.0% (18/18) | **78.3% (18/23)** | **0.8780** | **4.0% (1/25)** |
| **Text + Tactic Features** | 83.87% (26/31) | 100.0% (18/18) | **78.3% (18/23)** | **0.8780** | **28.0% (7/25)** |
| **Text + Tactics + URL Features (Model D)** | 83.87% (26/31) | 100.0% (18/18) | **78.3% (18/23)** | **0.8780** | **32.0% (8/25)** |

---

## 2. Step 7 Architectural Findings
1. **Redundancy of Explicit Tactic Vectors**:
   - Character n-grams already capture the lexical patterns associated with scam tactics (e.g., suspension threats, urgent deadlines).
   - Adding explicit binary tactic flags provided **0.0% gain in F1** on the text benchmark.
2. **Elevated False Positives on Benign Urgency**:
   - Combining tactic indicators directly into the statistical classifier caused the model to penalize legitimate messages triggering benign urgency or verification tactics, elevating the hard-negative FPR from 4.0% (1/25) to 32.0% (8/25).
3. **Architectural Decision**:
   - Deterministic tactic and URL analysis remain more appropriately represented in the forensic evidence layer rather than being unrestricted statistical classifier features.
   - This conclusion is specifically scoped to the evaluated Phase 13 benchmark and does not claim that tactic/URL features are universally harmful in all machine learning configurations.
