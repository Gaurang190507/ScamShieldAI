# ScamShield AI — Phase 13 Data Leakage Audit Report

**Audit Date**: 2026-10-02T13:32:33.680908+00:00  
**Status**: **PASS**  
**Audit Invariant**: Strict Group-Level Disjoint Splitting (Zero Group Leakage, Zero String Overlap)

---

## 1. Summary Metrics

| Audit Check | Measured Value | Threshold Requirement | Compliance |
| :--- | :--- | :--- | :--- |
| **Train vs. UCI SMS Exact Overlap** | 0 | 0 | PASS |
| **Train vs. UCI SMS Normalized Overlap** | 0 | 0 | PASS |
| **Train vs. Phase 7 Semantic Ref Exact Overlap** | 0 | 0 | PASS |
| **Train vs. Phase 7 Semantic Ref Normalized Overlap**| 0 | 0 | PASS |
| **Train vs. Phase 12 Evaluation Exact Overlap** | 0 | 0 | PASS |
| **Train vs. Val Exact String Overlap** | 0 | 0 | PASS |
| **Train vs. Val Normalized String Overlap** | 0 | 0 | PASS |
| **Train vs. Val Pattern Group Overlap** | 0 | 0 | PASS |
| **Train vs. Test Exact String Overlap** | 0 | 0 | PASS |
| **Train vs. Test Normalized String Overlap** | 0 | 0 | PASS |
| **Train vs. Test Pattern Group Overlap** | 0 | 0 | PASS |
| **Val vs. Test Exact String Overlap** | 0 | 0 | PASS |
| **Val vs. Test Pattern Group Overlap** | 0 | 0 | PASS |
| **Augmentation Group Split Crossings** | 0 | 0 | PASS |

---

## 2. Split Partition Sizes
- **Training Set (`train.jsonl`)**: 55 samples
- **Validation Set (`val.jsonl`)**: 20 samples
- **Test Set (`test.jsonl`)**: 31 samples
- **Hard Negatives Subset (`hard_negatives.jsonl`)**: 25 samples
- **Multilingual Subset (`multilingual_cases.jsonl`)**: 24 samples
- **Obfuscation Subset (`obfuscated_cases.jsonl`)**: 20 samples
- **Novel Patterns Subset (`novel_patterns.jsonl`)**: 16 samples

---

## 3. Verification Details
- **String Normalization Method**: Lowercase conversion followed by non-alphanumeric stripping regex (`\W+`).
- **Cluster Isolation**: Group identifiers (`pattern_group_id`) are unique per partition. Augmented pairs strictly share the same group ID and reside exclusively within the same split.
- **Audit Conclusion**: The Phase 13 evaluation datasets are completely leak-free and mathematically isolated from historical training corpora and internal evaluation partitions.
