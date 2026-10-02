# ScamShield AI — Phase 16 Generalization Gap & Cross-Phase Audit

## 1. Executive Summary
This report quantifies the generalization gap between historical benchmark performance and independent real-world performance.

## 2. Cross-Phase Benchmark Comparison Table
| Evaluation Metric | Phase 3 (Historical UCI) | Phase 12 (Consolidated Benchmark) | Phase 16 (Independent Real-World) | Phase 16 vs Phase 12 Delta | Phase 16 vs Phase 3 Delta |
|---|---|---|---|---|---|
| **Overall Accuracy** | 98.25% | 50.00% | **46.67%** | -3.33% | **-51.58%** |
| **Scam Precision** | ~98.0% | 86.67% | **84.21%** | -2.46% | -13.79% |
| **Scam Recall** | ~95.0% | 27.08% | **26.23%** | -0.85% | **-68.77%** |
| **Scam F1 Score** | ~96.5% | 0.4127 | **0.4000** | -0.0127 | -0.5650 |
| **Hard-Negative FPR** | <2.0% | 7.69% | **6.67%** | -1.02% (Improvement) | +4.67% |

## 3. Generalization Gap Diagnosis

### 3.1 The Historical Generalization Cliff (-51.58% Accuracy)
The historical UCI SMS Spam dataset (collected 2011–2012) represents a severely degraded, obsolete threat model dominated by simplistic promotional text (`WINNER!`, `Ring tones`).
When evaluated against modern Indian cybercrime patterns (digital arrest, electricity cutoff, fake e-challans, QR payment traps), the frozen Phase 3 TF-IDF model experiences a **massive 51.58 percentage point drop in accuracy** and a **68.77 percentage point drop in recall**.

### 3.2 High Precision Resilience (84.21% Precision)
Remarkably, when the system *does* emit a `likely_scam` verdict, it remains highly trustworthy:
- Phase 12 Precision: 86.67%
- Phase 16 Precision: 84.21%
This demonstrates that false alarms on general text remain tightly controlled, making high-confidence alerts operationally actionable.

### 3.3 Subgroup Generalization Persistence
The subgroup measurements in Phase 16 mirror the exact failure modes discovered in Phase 12:
- **Native Devanagari Hindi**: 0.00% recall in Phase 12, 0.00% recall in Phase 16.
- **Romanized Hinglish**: 33.33% recall in Phase 12, 33.33% recall in Phase 16.
- **Common Scams**: 40.00% recall in Phase 12, 45.00% recall in Phase 16.
- **Hard-Negative FPR**: 7.69% in Phase 12, 6.67% in Phase 16.

> [!NOTE]
> This striking parity proves that Phase 12 results were not an artifact of test set selection, but an authentic, reproducible characteristic of the frozen Phase 1–15 architecture.
