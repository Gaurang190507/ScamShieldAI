# Human Annotation Pilot Artifacts 🧪

## 1. Overview & Objective
This directory contains the artifacts for the **ScamShield AI Human Annotation Pilot**.
The goal of this pilot is to evaluate whether the ScamShield schema and annotation guidelines function properly in practice on a diverse, representative slice of real-world text.

> [!IMPORTANT]
> **Isolation Policy**:
> These records are **evaluation and benchmark artifacts**.
> They must **NOT** be merged into training data partitions.

---

## 2. Directory Contents

| File | Description |
| :--- | :--- |
| `annotation_instructions.md` | Formal step-by-step annotation manual, review workflow, and multi-annotator agreement guidelines. |
| `annotation_template.jsonl` | Blank annotation template generated for annotators to populate. |
| `pilot_dataset.jsonl` | Completed and validated pilot dataset containing 60 annotated samples with grounded evidence spans. |

---

## 3. Pilot Cohort Composition (60 Samples)

The 60 pilot messages were deterministically sampled from the verified UCI SMS collection across 7 distinct strata:

1. **Benign Conversational (15 samples)**: Everyday personal, social, and logistical messages (`label = "non_scam"`, `tactics = []`).
2. **Hard Negatives — Urgency (8 samples)**: Legitimate messages containing time-sensitive words ("now", "quick", "asap", "today") to test false-alarm resistance.
3. **Hard Negatives — Financial / Billing (7 samples)**: Legitimate messages containing billing queries, banking details, or loan references to confirm that payment words alone do not trigger a scam classification.
4. **Scams with Links (12 samples)**: Malicious prize, sweepstakes, and WAP lures containing redirection links (`tactics = ["link_redirection", ...]`).
5. **Scams with Lottery / Prizes (8 samples)**: Deceptive operator alerts promising cash/vacations via premium-rate telephone lines (`tactics = ["reward_claim", ...]`).
6. **Commercial Spam Boundary (5 samples)**: Unsolicited marketing (ringtones, dating chat, club promos) testing the critical distinction between unsolicited commercial spam and fraudulent scams.
7. **Ambiguous / Minimal Context (5 samples)**: Terse snippets testing uncertainty calibration (`label_confidence = "low"`, `known_unknown_status = "unknown"`).

---

## 4. Summary Metrics
- **Total Samples**: 60
- **Non-Scam (`non_scam`)**: 39 (65.0%)
- **Scam (`scam`)**: 21 (35.0%)
- **Tactics Extracted**: 9 distinct behavioral tactics (`reward_claim`, `link_redirection`, `payment_request`, `urgency`, `impersonation`, `verification_request`, `romance_manipulation`, `personal_information_request`, `refund_claim`).
- **Verbatim Evidence Anchoring**: 100% of tactics anchored to exact substring evidence.
- **Validation**: 100% passed via `DatasetValidator` with zero schema or enum errors.
