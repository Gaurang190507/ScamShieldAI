# Evaluation Subset: Novel & Emerging Patterns 🔍

## Purpose
The `novel_patterns` subset tests the system's ability to detect out-of-distribution, emerging, or previously unseen scam methodologies.

## Policy & Governance
- **Zero Training Overlap**: All samples must belong to `known_unknown_status = "held_out"` or `"unknown"`.
- **Pattern Group Reservation**: Pattern groups reserved for this folder are completely excluded from initial feature tuning, vocabulary building, and model training.
- **Evaluation Objective**: Validates the novelty detection engine's capacity to output `Potentially emerging pattern` or `Suspicious` rather than misclassifying an unknown scam as benign (`Low risk`) due to unfamiliar terminology.
- No samples are fabricated at this stage.
