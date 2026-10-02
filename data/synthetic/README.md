# Synthetic Data Policy 🧪

This directory is designated for synthetic and semi-synthetic samples in the ScamShield AI project.

## Purpose of Synthetic Data

Synthetic data serves specific, disciplined roles during system development and verification:

1. **Controlled Edge Cases**: Simulating rare communication layouts, unusual punctuation stylings, or extreme character-level obfuscations.
2. **Rare Tactic Combinations**: Constructing samples pairing unusual combinations of tactics (e.g., romance manipulation combined with QR code requests) that are underrepresented in public corpora.
3. **Adversarial Stress Testing**: Testing the resilience of heuristic rules, tokenizers, and future ML detectors against evasive formatting, homoglyphs, and prompt injections.
4. **Testing Novelty & Anomaly Detection**: Generating out-of-distribution patterns to validate whether novelty detection mechanisms correctly distinguish unseen tactics from known patterns.
5. **Multilingual & Cross-Lingual Variations**: Testing code-switching or regional dialect variations before extensive field data is acquired.
6. **Local Development & Debugging**: Providing lightweight, privacy-safe mock instances for unit tests and local pipeline verification without exposing sensitive user submissions.

## Mandatory Data Governance Rules

> [!CAUTION]
> **Synthetic data must NEVER be represented as real-world empirical observations.**

All synthetic records must adhere to the following strict requirements:

- **Provenance Tracking**: Every synthetic sample must set `source_type = "synthetic"`.
- **Source Reference**: The `source_reference` field must explicitly identify the generator method, script, or template used (e.g., `script:synthetic_tactic_combos_v1`).
- **No Evaluation Contamination**: Synthetic samples must not be mixed into the standard empirical benchmark test sets (`data/evaluation/standard/`).
- **Zero Hallucinated Datasets**: Mass-generation of synthetic samples without a defined hypothesis, controlled variable design, and annotator review is strictly prohibited.

No synthetic data has been generated at this stage.
