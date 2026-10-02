# Phase 7 Evaluation Report: Semantic Similarity & Known/Unknown Pattern Detection

## 1. Executive Summary

Phase 7 introduces the **Semantic Similarity and Novelty Detection Layer** for ScamShield AI. This component enables the system to:
1. Embed messages into a dense semantic representation using a local, deterministic transformer.
2. Search against a strictly isolated reference corpus of historical benchmark messages (derived exclusively from the Phase 3 training partition).
3. Retrieve top-$K$ semantically similar reference messages without relying on labels for retrieval.
4. Calculate an uncalibrated relative `semantic_novelty_score` to measure vector distance from the reference corpus.

### Core Architectural Distinctions
$$\text{SEMANTIC NOVELTY} \ne \text{SCAM VERDICT}$$
$$\text{SEMANTIC SIMILARITY} \ne \text{SCAM PROBABILITY}$$

* **Novelty != Scam**: A novel message is simply one that exhibits low cosine similarity to the known reference corpus. It may be a benign message with unusual vocabulary, a personal conversational exchange, or an emerging, uncataloged scam pattern.
* **Similarity != Scam Probability**: A message with high semantic similarity to reference messages is simply close in vector space. Whether it is dangerous depends on the nature of the match and downstream evidence, not similarity magnitude alone.
* **Phase 7 Boundaries**: Phase 7 does **not** output an overall scam risk score or classification label. It provides semantic and evidentiary signals only.

---

## 2. Dataset & Split Partitioning

Strict separation was enforced by loading the authoritative Phase 3 leakage-safe group partitions (`data/processed/preprocessed/uci_sms_spam.jsonl`, `random_state=42`).

| Split Partition | Sample Count | Scam Samples | Non-Scam Samples | Role in Phase 7 |
| :--- | :---: | :---: | :---: | :--- |
| **TRAIN (Reference Corpus)** | **3,881** | 520 (13.4%) | 3,361 (86.6%) | **Sole Reference Index**. Embedded and queried against. |
| **VALIDATION (Query Set)** | **837** | 104 (12.4%) | 733 (87.6%) | Query set for threshold sensitivity and distribution analysis. |
| **TEST (Held-Out Evaluation)** | **856** | 123 (14.4%) | 733 (85.6%) | Held-out confirmation query set. |
| **Total Canonical Dataset** | **5,574** | **747** | **4,827** | Exact canonical preservation. |

> **Dataset Provenance Note**: The UCI SMS Spam Collection was historically annotated with `spam` / `ham` labels. In ScamShield AI Phase 3, these were normalized to `scam` / `non_scam` for baseline classification. As documented across the project, historical SMS spam does not equate to verified real-world scam evidence. The labels in this report represent the project's normalized benchmark labels and do not imply independently verified scam provenance.

---

## 3. Embedding Model Specifications

* **Model Identifier**: `sentence-transformers/all-MiniLM-L6-v2`
* **Architecture**: 6-layer MiniLM transformer, 12 attention heads, 384 hidden dimension.
* **Embedding Dimension**: **384** float32 values.
* **Normalization Method**: Unit L2 normalization ($\|\vec{v}\|_2 = 1.0$), ensuring $\vec{u} \cdot \vec{v}$ directly computes cosine similarity.
* **Similarity Metric**: Cosine similarity bounded strictly to $[-1.0, 1.0]$.
* **Operational Mode**: **100% Offline & Local**. Following initial one-time local acquisition, model execution runs strictly offline (`local_files_only=True`); no external network requests, DNS queries, or cloud APIs are invoked.

---

## 4. Leakage Protection & Isolation Verification

To guarantee valid evaluation, the system enforces programmatic leakage guards verified by `tests/test_semantic_leakage.py`:

| Leakage Dimension | Allowed Count | Measured Count | Status |
| :--- | :---: | :---: | :---: |
| **Sample ID Overlap (Reference vs Validation)** | 0 | **0** | **PASS** |
| **Sample ID Overlap (Reference vs Test)** | 0 | **0** | **PASS** |
| **Exact Verbatim Text Overlap (Reference vs Validation)** | 0 | **0** | **PASS** |
| **Exact Verbatim Text Overlap (Reference vs Test)** | 0 | **0** | **PASS** |
| **Normalized Text Overlap (Reference vs Validation)** | 0 | **0** | **PASS** |
| **Normalized Text Overlap (Reference vs Test)** | 0 | **0** | **PASS** |
| **Same-Sample Retrieval Violations** | 0 | **0** | **PASS** |

If a query sample ID exists in the reference index, the system raises an immediate `ValueError("Data leakage violation...")` when `disallow_same_id=True`.

---

## 5. Retrieval & Similarity Distributions

### 5.1 Validation Set Query Distribution (837 samples)

Validation queries were analyzed against the 3,881-sample training reference index:

| Metric | Overall (All 837) | Scam-Labeled Queries (104) | Non-Scam-Labeled Queries (733) |
| :--- | :---: | :---: | :---: |
| **Mean Top-1 Similarity** | 0.5660 | **0.7151** | 0.5448 |
| **Median Top-1 Similarity** | 0.5348 | **0.6773** | 0.5251 |
| **Standard Deviation** | 0.1442 | 0.1929 | 0.1196 |
| **Min Top-1 Similarity** | 0.2469 | 0.3546 | 0.2469 |
| **Max Top-1 Similarity** | 0.9995 | 0.9995 | 0.9412 |
| **Mean Semantic Novelty** | 0.4340 | **0.2849** | 0.4552 |

> **Contextual Observation**: Scam-labeled queries in the validation partition exhibit a higher average similarity to the training reference corpus ($0.7151$) than benign queries ($0.5448$). This reflects the repetitive, template-driven nature of commercial promotional spam in the 2004 UCI corpus (e.g., prize draws, ringtones, mobile upgrade offers). Benign messages exhibit wider conversational and lexical diversity. However, semantic similarity alone is **not** a scam classifier or scam probability.

### 5.2 Held-Out Test Set Confirmation (856 samples)
* **Overall Top-1 Similarity**: Mean = $0.5805$, Median = $0.5557$.
* **Scam-Labeled Queries Top-1 Similarity**: Mean = **0.7679**, Median = **0.7944**.
* **Non-Scam-Labeled Queries Top-1 Similarity**: Mean = **0.5491**, Median = **0.5350**.
* The test partition confirms stable semantic behavior without unexpected distribution drift.

---

## 6. Threshold Sensitivity Analysis on Validation Set

To evaluate sensitivity to similarity thresholds, we inspected the distribution of validation samples across candidate cutoffs:

| Candidate Cutoff $\theta$ | % Falling into Similar Region ($\ge \theta$) | % Falling into Divergent Region ($< \theta$) | % Scam-Labeled $\ge \theta$ | % Non-Scam-Labeled $\ge \theta$ |
| :---: | :---: | :---: | :---: | :---: |
| **0.50** | 64.4% | 35.6% | 85.6% | 61.4% |
| **0.55** | 45.2% | 54.8% | 72.1% | 41.3% |
| **0.60** | 30.6% | 69.4% | 68.3% | 25.2% |
| **0.65** | 21.9% | 78.1% | 56.7% | 16.9% |
| **0.70** | **15.9%** | **84.1%** | **48.1%** | **11.3%** |
| **0.75** | 11.0% | 89.0% | 40.4% | 6.8% |
| **0.80** | 9.0% | 91.0% | 37.5% | 4.9% |
| **0.85** | 5.5% | 94.5% | 30.8% | 1.9% |
| **0.90** | 4.2% | 95.8% | 27.9% | 0.8% |

### What This Table Demonstrates
* The table describes the fraction of validation samples that would be categorized as similar to the reference corpus at different similarity thresholds.
* It does **NOT** prove that $0.70$ (or any other cutoff) is an optimal, calibrated, or production threshold.
* The table serves as an empirical sensitivity guide for Phase 7 exploratory analysis and can inform future threshold selection once a dedicated novelty benchmark with ground-truth novelty labels is established. A threshold must not be chosen based on scam classification metrics alone.

### Provisional Operational Bands for Phase 7 Analysis
For the purpose of Phase 7 exploratory reporting, the system adopts three provisional operational status bands:
1. **`similar_to_known`** ($\text{Top-1 Sim} \ge 0.70$, Novelty $\le 0.30$):
   * Captures messages exhibiting high semantic similarity to an existing reference pattern.
2. **`moderately_novel`** ($0.50 \le \text{Top-1 Sim} < 0.70$, $0.30 < \text{Novelty} \le 0.50$):
   * Reflects intermediate semantic proximity with noticeable phrasing differences.
3. **`potentially_novel`** ($\text{Top-1 Sim} < 0.50$, Novelty $> 0.50$):
   * Reflects substantial vector-space divergence from the reference corpus.

> **Important**: These bands are **provisional and exploratory**. They are **not calibrated probabilities**, confidence scores, or scam verdicts.

---

## 7. Pilot Dataset Evaluation (60 samples)

The 60-sample human-annotated pilot dataset contains an explicit qualitative `known_unknown_status` field. We evaluated how semantic similarity correlates with these human annotations:

* **Human Annotated "Known" ($N=58$)**:
  * Mean Top-1 Similarity: **0.6743** (Median: 0.6005, Max: 1.0000).
* **Human Annotated "Unknown" ($N=2$)**:
  * Mean Top-1 Similarity: **0.5057** (Median: 0.5057, Range: [0.4979, 0.5136]).

### Disagreements & Clarification of Terminology
It is critical to distinguish:
* **Human Qualitative Annotation**: `known` vs `unknown` reflects whether the human annotator recognized the underlying scenario or saw it as an unassigned pattern.
* **Semantic System Output**: `similar_to_known`, `moderately_novel`, and `potentially_novel` reflect dense vector cosine distance relative to the 2004 training corpus.

These two concepts do not always coincide:
1. **Annotated "Known" but Low Semantic Similarity ($< 0.50$)**:
   * Example `uci_sms_0007`: *"Even my brother is not like to speak with me. They treat me like aids patent."* (Top-1 Sim: **0.3959**).
   * Example `uci_sms_0479`: *"Tension ah?what machi?any problem?"* (Top-1 Sim: **0.3061**).
   * *Explanation*: The human annotator recognized these messages as common human conversational chatter (hence "known"). However, their specific colloquial Hinglish / regional idioms ("machi", "tension ah") have no close semantic twins in the 2004 UK-dominated reference index. This disagreement is expected and highlights that human familiarity differs from vector corpus density.
2. **Annotated "Unknown"**:
   * Example `uci_sms_0044`: *"WHO ARE YOU SEEING?"* (Top-1 Sim: **0.5136**).
   * Example `uci_sms_0497`: *"Got meh... When?"* (Top-1 Sim: **0.4979**).
   * *Explanation*: Both fall near the $0.50$ provisional operational boundary, consistent with an unassigned or ambiguous message pattern.

---

## 8. Hard Case In-Depth Analysis

Six representative cases were examined to assess the semantic layer qualitatively:

### Case A: High-Similarity UCI Benchmark Sample Labeled Scam
* **Sample ID**: `uci_sms_0010` | **Normalized Benchmark Label**: `scam`
* **Text**: *"Had your mobile 11 months or more? U R entitled to Update to the latest colour mobiles with camera for Free! Call The Mobile Update Co FREE on 08002986030"*
* **Semantic Analysis**:
  * Top-1 Sim: **0.9021** | Novelty: **0.0979** | Status: **`similar_to_known`**
  * Nearest Scam Sim: **0.9021** | Nearest Non-Scam Sim: None in top-5
* **Top Neighbors**:
  1. `uci_sms_0320` (Sim: 0.9021 | SCAM): *"December only! Had your mobile 11mths+? You are entitled to update to the latest colour camera mo..."*
  2. `uci_sms_2809` (Sim: 0.9021 | SCAM): *"December only! Had your mobile 11mths+? You are entitled to update to the latest colour camera mo..."*
* **Interpretation**: High similarity to established telemarketing promotions in the training corpus. Note that this label reflects the normalized UCI benchmark label and not verified real-world scam provenance.

### Case B: High-Similarity Legitimate / Non-Scam Benchmark Sample
* **Sample ID**: `uci_sms_0188` | **Normalized Benchmark Label**: `non_scam`
* **Text**: *"Haha awesome, be there in a minute"*
* **Semantic Analysis**:
  * Top-1 Sim: **0.8787** | Novelty: **0.1213** | Status: **`similar_to_known`**
  * Nearest Scam Sim: None in top-5 | Nearest Non-Scam Sim: **0.8787**
* **Top Neighbors**:
  1. `uci_sms_4452` (Sim: 0.8787 | NON_SCAM): *"Awesome, be there in a minute"*
  2. `uci_sms_0279` (Sim: 0.5556 | NON_SCAM): *"Awesome, I'll see you in a bit"*
* **Interpretation**: Common social dialogue with a close semantic neighbor in the reference corpus. Demonstrates that high similarity does not imply scam.

### Case C: Low-Similarity UCI Benchmark Sample Labeled Scam
* **Sample ID**: `uci_sms_0069` | **Normalized Benchmark Label**: `scam`
* **Text**: *"Did you hear about the new "Divorce Barbie"? It comes with all of Ken's stuff!"*
* **Semantic Analysis**:
  * Top-1 Sim: **0.3733** | Novelty: **0.6267** | Status: **`potentially_novel`**
  * Nearest Scam Sim: None in top-5 | Nearest Non-Scam Sim: **0.3733**
* **Top Neighbors**:
  1. `uci_sms_2892` (Sim: 0.3733 | NON_SCAM): *"Shuhui has bought ron's present it's a swatch watch..."*
  2. `uci_sms_3214` (Sim: 0.3545 | NON_SCAM): *"We got a divorce. Lol. She.s here"*
* **Interpretation**: A commercial joke service message labeled spam in the UCI collection. Because of its joke format, it diverges sharply from standard financial and lottery lures. The novelty score flags it as `potentially_novel` relative to the training index. This reflects benchmark distance, not verified real-world scam evidence.

### Case D: Low-Similarity Non-Scam Benchmark Sample
* **Sample ID**: `uci_sms_0110` | **Normalized Benchmark Label**: `non_scam`
* **Text**: *"I know! Grumpy old people. My mom was like you better not be lying. Then again I am always the one to play jokes..."*
* **Semantic Analysis**:
  * Top-1 Sim: **0.3611** | Novelty: **0.6389** | Status: **`potentially_novel`**
  * Nearest Scam Sim: None in top-5 | Nearest Non-Scam Sim: **0.3611**
* **Top Neighbors**:
  1. `uci_sms_1067` (Sim: 0.3611 | NON_SCAM): *"No my mum went 2 dentist."*
  2. `uci_sms_5037` (Sim: 0.3603 | NON_SCAM): *"How many times i told in the stage all use to laugh..."*
* **Interpretation**: Unique narrative dialogue with no close syntactic analog in the training set. Novelty score is high, demonstrating that benign conversational speech is often novel.

### Case E: Human-Labelled "Unknown" Pilot Sample
* **Sample ID**: `uci_sms_0497` | **Human Status**: `unknown` | **Label**: `non_scam`
* **Text**: *"Got meh... When?"*
* **Semantic Analysis**:
  * Top-1 Sim: **0.4979** | Novelty: **0.5021** | Status: **`potentially_novel`**
  * Nearest Neighbor: `uci_sms_0561` (Sim: 0.4979 | NON_SCAM): *"Got it. Coz ijara haven't heard from them."*
* **Interpretation**: Colloquial inquiry with unassigned pattern status in the pilot annotation. The semantic layer independently confirms divergence from the standard training corpus (Top-1 Sim $< 0.50$).

### Case F: Human-Labelled "Known" Pilot Sample
* **Sample ID**: `uci_sms_0013` | **Human Status**: `known` | **Label**: `scam`
* **Text**: *"URGENT! You have won a 1 week FREE membership in our £100,000 Prize Jackpot! Txt the word: CLAIM to No: 81010 T&C www.dbuk.net LCCLTD POBOX 4403LDNW1A7RW18"*
* **Semantic Analysis**:
  * Top-1 Sim: **0.8654** | Novelty: **0.1346** | Status: **`similar_to_known`**
  * Nearest Neighbor: `uci_sms_0419` (Sim: 0.8654 | SCAM): *"FREE entry into our £250 weekly competition just text the word WIN to 80086 NOW..."*
* **Interpretation**: Classic prize jackpot spam. Matches the dense cluster of prize lures in the reference training partition.

---

## 9. Performance & Compute Telemetry

* **Reference Corpus Size**: 3,881 samples.
* **Embedding Matrix Size**: $3881 \times 384 \times 4\text{ bytes} \approx 5.96\text{ MB}$.
* **Inference Throughput**: **101.1 samples / sec** (Local CPU, PyTorch 2.14 / all-MiniLM-L6-v2).
* **Reference Search Latency**: $< 1.2\text{ ms}$ per query using optimized NumPy BLAS matrix multiplication.
* **Vector Database Necessity**: **Zero**. At current scales ($\sim 5,000$ records), in-memory NumPy cosine similarity provides instant sub-millisecond retrieval with absolute determinism and zero third-party database dependency.

---

## 10. Automated Test Suite Results

The test suite was executed using the standard command:
```powershell
python -m unittest discover tests
```
Output:
```text
Ran 206 tests in 10.333s

OK
```
* **Phase 1–6 Existing Tests**: 183 / 183 PASS
* **Phase 7 New Tests**: 23 / 23 PASS
  * `tests/test_semantic_similarity.py` (8 tests)
  * `tests/test_novelty_detection.py` (8 tests)
  * `tests/test_semantic_leakage.py` (7 tests)
* **Total Project Tests**: **206 / 206 PASS (100%)**

---

## 11. Documentation Integrity Repair

This report was updated to adhere to project documentation integrity standards:
* **Threshold Terminology Corrected**: Removed claims of $0.70$ being a "calibrated", "optimal", or "production" threshold. Clarified that $0.70$ is a provisional operational boundary for exploratory categorization.
* **Threshold Table Clarified**: Explained that the sensitivity table demonstrates distribution behavior across cutoffs rather than proving an optimal boundary.
* **UCI Spam vs Verified Scam Terminology**: Replaced terms like "Novel Scam" with "Low-Similarity UCI Benchmark Sample Labeled Scam". Explicitly noted that UCI labels represent normalized benchmark labels rather than verified real-world scam evidence.
* **Discrimination Language Removed**: Removed references to semantic similarity being a "scam discriminator". Reaffirmed that `semantic similarity != scam probability` and `semantic novelty != scam verdict`.
* **Human Known/Unknown vs Semantic Status**: Clearly distinguished human qualitative annotation (`known`/`unknown`) from dense vector semantic status (`similar_to_known`, `moderately_novel`, `potentially_novel`).
* **Hard Case Terminology Corrected**: Aligned Case A through Case F descriptions with verified empirical provenance.
* **Test Invocation Documented**: Replaced placeholder with the exact execution command (`python -m unittest discover tests`).
* **Implementation Invariants Preserved**: Model, embeddings, reference index, and code remain 100% intact and unchanged. Phases 3–6 remain frozen.
