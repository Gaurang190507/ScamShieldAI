# ScamShield AI — Phase 8: Multi-Signal Risk Aggregation & Forensic Audit Specification

## 1. Executive Summary & Objective

**Phase 8** implements a deterministic, explainable, and fully auditable multi-signal risk aggregation and forensic decision engine for ScamShield AI.

Up to Phase 7, ScamShield AI created independent, specialized detection components:
- **Phase 3**: Statistical text classification (TF-IDF + Logistic Regression, decision threshold $\tau = 0.30$)
- **Phase 4**: Passive offline structural URL risk analysis (string syntax heuristics, zero network access)
- **Phase 5**: Hybrid text + URL baseline experiment (frozen research milestone, intentionally excluded from runtime aggregation to prevent double-counting)
- **Phase 6**: Behavioral scam tactic detection & grounded character-level evidence spans (18 tactic rules, offset validation)
- **Phase 7**: Semantic embeddings, top-K nearest-neighbor retrieval from the frozen training reference corpus, and relative novelty quantification (NumPy cosine similarity)

The objective of Phase 8 is **not** to train a new machine learning model or introduce black-box aggregators. Rather, Phase 8 synthesizes these heterogeneous, high-dimensional signals into a unified, transparent case-level assessment with an immutable forensic audit trail.

---

## 2. Hard Architectural & Safety Constraints

1. **Zero Black-Box Pseudo-Probabilities**: Arbitrary weighted linear formulas (e.g., $0.4 \cdot P_{\text{text}} + 0.3 \cdot S_{\text{url}} + 0.3 \cdot S_{\text{tactic}}$) are strictly prohibited. Such formulas manufacture an illusion of mathematical confidence while erasing critical contradictions between independent signals.
2. **Explicit Distinction of Signal Dimensions**:
   - *Statistical Text Score*: Vocabulary likelihood estimated from TF-IDF n-grams.
   - *Behavioral Tactics*: Verbatim, contextual exploitation patterns (e.g., OTP theft, fake urgency, payment demands).
   - *Structural URL Risk*: Anomaly heuristics within the URL syntax (IP addresses, deep paths, obfuscation).
   - *Semantic Similarity*: Vector proximity to known training reference exemplars.
   - *Semantic Novelty*: Geometric vector distance from the reference distribution. **Novelty indicates atypical phrasing or new vocabulary—it never denotes scam culpability.**
3. **Transparent Contradiction Handling**: When signals actively diverge (e.g., high statistical score but zero tactics and clean URL, or low statistical score with a weaponized URL), the engine reports `mixed_signals`, documents the conflicting evidence, and attaches forensic cautions.
4. **Phase 5 Exclusion Invariant**: Phase 5 was an experimental comparison evaluating joint text-and-URL features. Ingesting Phase 5 outputs into the runtime aggregator would double-count Phase 3 and Phase 4 features. The aggregator explicitly sets `audit.phase5_used = False`.
5. **100% Offline & Deterministic Execution**: Zero socket connections, zero DNS resolution, zero external lookups, zero LLM calls, zero FAISS/Chroma dependencies. All evaluations are reproducible and hermetic.

---

## 3. Canonical Schema Specification

The aggregation engine produces standardized dataclasses defined in `src/aggregation/schemas.py`:

### 3.1 `EvidenceItem`
Atomic, traceable unit of evidence extracted from any upstream component:
```json
{
  "evidence_id": "ev_001",
  "source": "phase3_classifier | phase4_url | phase6_tactic | phase7_similarity",
  "type": "classification | url_signal | tactic | semantic_context",
  "name": "scam_probability | ip_based_hostname | credential_request | top1_similarity",
  "strength": "supporting | contradicting | contextual | weak",
  "value": 0.9421,
  "text": "verify your password",
  "start": 74,
  "end": 94,
  "url": "http://192.168.1.1/login",
  "reason": "Explicit credential harvesting."
}
```

### 3.2 `AssessmentSummary`
High-level case categorization:
```json
{
  "status": "likely_scam | likely_non_scam | mixed_signals | insufficient_evidence",
  "evidence_level": "high | moderate | low",
  "signal_consistency": "strong_agreement | moderate_agreement | mixed | insufficient"
}
```

### 3.3 `ExplanationObject`
Deterministic, template-generated human-readable rationale:
```json
{
  "summary": "Assessment: LIKELY SCAM (HIGH evidence level)...",
  "reasons": [
    "Statistical text classifier indicates scam pattern (estimated score: 0.9421, threshold: 0.30).",
    "Detected 2 behavioral tactic(s): account_suspension, credential_request.",
    "Passive URL analysis flagged structural risk (max heuristic score: 0.85)."
  ],
  "cautions": [
    "Upstream signals actively disagree..."
  ]
}
```

### 3.4 `AuditObject`
Forensic verification record guaranteeing zero external access and pipeline compliance:
```json
{
  "phase3_used": true,
  "phase4_used": true,
  "phase5_used": false,
  "phase6_used": true,
  "phase7_used": true,
  "network_access": false,
  "external_lookup": false,
  "final_decision_rule": "rule_strong_scam_classifier_and_severe_tactics",
  "evidence_count": 6,
  "contradiction_count": 0,
  "timestamp": "2026-10-02T14:17:15.123456+00:00"
}
```

---

## 4. Deterministic Decision Rules & Evaluator Logic

The rule engine in `RiskAggregator` evaluates inputs through a prioritized deterministic ladder:

| Rule Identifier | Trigger Condition | Status | Evidence Level | Consistency | Rationale |
| :--- | :--- | :--- | :--- | :--- | :--- |
| `rule_empty_content` | `text.strip() == ""` | `insufficient_evidence` | `low` | `insufficient` | Empty content cannot be assessed. |
| `rule_strong_scam_classifier_and_severe_tactics` | $P_{\text{cls}} \ge 0.30 \land (N_{\text{high\_tactic}} \ge 1 \lor (N_{\text{tactic}} \ge 2 \land \text{URL}_{\text{high}}))$ | `likely_scam` | `high` | `strong_agreement` | Strong multi-signal corroboration across statistical text and high-severity behavioral tactics. |
| `rule_scam_classifier_and_tactics` | $P_{\text{cls}} \ge 0.30 \land (N_{\text{tactic}} \ge 1 \lor \text{URL}_{\text{high}})$ | `likely_scam` | `moderate` | `moderate_agreement` | Moderate multi-signal scam evidence. |
| `rule_critical_tactics_exploitation_override` | $N_{\text{high\_tactic}} \ge 2 \lor \text{otp\_request} \in T \lor \text{credential\_request} \in T$ | `likely_scam` | `high` | `moderate_agreement` (or `mixed`) | Direct credential or OTP harvesting represents acute behavioral exploitation regardless of general TF-IDF bag-of-words score. |
| `rule_clean_non_scam_unanimous` | $P_{\text{cls}} < 0.30 \land N_{\text{tactic}} == 0 \land \text{URL}_{\text{clean\_or\_absent}}$ | `likely_non_scam` | `low` | `strong_agreement` | Complete absence of suspicious signals across text, tactics, and URLs. |
| `rule_contradiction_classifier_scam_clean_behavior` | $P_{\text{cls}} \ge 0.30 \land N_{\text{tactic}} == 0 \land \text{URL}_{\text{clean\_or\_absent}}$ | `mixed_signals` | `moderate` | `mixed` | Text classifier flagged lexical similarity to scams, but zero behavioral manipulation or URL threats exist. |
| `rule_contradiction_url_threat_low_text_score` | $P_{\text{cls}} < 0.30 \land \text{URL}_{\text{high}}$ | `mixed_signals` | `moderate` | `mixed` | Benign or low-scoring text paired with a high-risk URL anomaly (e.g., bare IP address or credential-stealing domain). |
| `rule_contradiction_tactics_present_low_classifier` | $P_{\text{cls}} < 0.30 \land N_{\text{tactic}} \ge 1$ | `mixed_signals` | `moderate` | `mixed` | Isolated behavioral tactic detected despite low statistical n-gram score. |
| `rule_ambiguous_signal_combination` | All other unclassified combinations | `mixed_signals` | `moderate` | `mixed` | Disagreement across edge-case signals. |

### Handling of Semantic Novelty
- The semantic novelty score $S_{\text{nov}} = 1.0 - \text{top1\_sim}$ measures distance from the training corpus.
- If $S_{\text{nov}} \ge 0.50$, the engine generates a cautionary note:
  > *"High semantic novelty score ($S_{\text{nov}}$): message diverges from the reference training corpus. Novelty indicates uncataloged vocabulary or pattern structure, not definitive fraud."*
- Semantic novelty is **never** used to override a non-scam assessment into a scam verdict.

---

## 5. Verification & Compliance Checklist

- [x] **No model retraining**: Phase 3, Phase 5, Phase 6, Phase 7 models and artifacts remain untouched.
- [x] **Phase 5 excluded**: Recorded as `phase5_used: false` in `AuditObject`.
- [x] **Zero network access**: Enforced offline via standard libraries; verified in audit object.
- [x] **Transparent contradictions**: Dedicated `mixed_signals` status with explicit conflicting evidence.
- [x] **Verbatim evidence grounding**: Character offsets and matched text spans preserved in `EvidenceItem`.
- [x] **Full serialization**: Complete roundtrip JSON compatibility verified.

---

## 6. Benchmark Scope & Dataset Limitations

> "The UCI SMS Spam Collection was originally annotated as spam/ham. ScamShield normalizes these labels to scam/non_scam for the benchmark classification task. These labels are not equivalent to verified real-world scam provenance."

Accordingly, the Phase 8 evaluation metrics describe **benchmark behavior** on held-out partitions and should not be interpreted as:
- real-world scam accuracy
- real-world false-positive rate
- real-world false-negative rate
- production scam detection performance

In held-out benchmark testing across the 733 non-scam-labeled samples:
- 714 (97.41%) were assigned `likely_non_scam`
- 17 (2.32%) were assigned `mixed_signals`
- 2 (0.27%) were assigned `likely_scam`

These figures describe behavior on the current benchmark and should not be interpreted as a measured real-world false-positive rate.
