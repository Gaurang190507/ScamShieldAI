# Evaluation Subset: Adversarial Stress Testing ⚔️

## Purpose
The `adversarial` evaluation subset contains samples engineered to intentionally evade naive pattern recognition, keyword heuristics, and superficial text classifiers.

## Attack Vectors Tested
- **Linguistic Obfuscation**: Zero-width spaces, leetspeak, homoglyphs (Cyrillic lookalikes), and strategic misspellings (e.g., `P@ssw0rd`, `b-a-n-k`).
- **Context Inversion**: Threat language disguised inside benign pleasantries or multi-turn conversational pretexts.
- **Evasive Links**: Link shorteners, redirect chains, punycode domains, and data URLs.
- **Benign Framing of Malicious Payloads**: Phishing prompts disguised as policy updates or legal disclaimers.

## Evaluation Objective
- Measures system robustness under active evasion attempts.
- Informs threshold calibration in the risk and explainability engines.
- No samples are fabricated at this stage.
