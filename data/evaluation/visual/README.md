# ScamShield AI — Phase 9B Visual Evaluation Artifacts

This directory contains the evaluation metrics, forensic analyses, and benchmark outputs for **Phase 9B: Visual Scam Classification**.

## File Index

- `phase9b_visual_evaluation.md`: Primary evaluation report detailing the comparative results across:
  - **Experiment A**: Text-Only baseline (Phase 3 reference model).
  - **Experiment B**: Visual-Only baseline (Phase 9B Logistic Regression).
  - **Experiment C**: Multimodal fusion (Text + Visual combination).
- `visual_hard_negative_analysis.md`: Detailed vulnerability analysis of visual features on benign UI screens possessing scam-like features (QR checkouts, OTP prompts, bank security alerts).
- `evaluation_results.json`: Raw structured machine-readable evaluation metrics, classifier weights, split distributions, and sample-by-sample classifications.

## Reproduction Command

To re-run the evaluation and regenerate all reports:
```bash
python -m src.vision --evaluate
```
