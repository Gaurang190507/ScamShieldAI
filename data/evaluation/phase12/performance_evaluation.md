# Phase 12: Performance & Execution Latency Benchmarking

## 1. Latency Benchmark Summary
Measured over 15 warm repetitions on local hardware (Windows, Python 3.13).

| Pipeline Component | Mean Latency | Median Latency | P95 Latency | P99 Latency |
|---|---|---|---|---|
| `phase3_text_classifier` | 0.65 ms | 0.53 ms | 1.06 ms | 1.39 ms |
| `phase4_url_scanner` | 0.40 ms | 0.36 ms | 0.57 ms | 0.65 ms |
| `phase6_tactic_detector` | 0.30 ms | 0.30 ms | 0.35 ms | 0.36 ms |
| `phase7_semantic_analyzer` | 31.75 ms | 26.94 ms | 58.56 ms | 91.45 ms |
| `phase8_risk_pipeline` | 21.00 ms | 21.00 ms | 24.21 ms | 25.38 ms |
| `phase11_investigation_service` | 24.27 ms | 23.22 ms | 29.73 ms | 33.56 ms |

## 2. Throughput & Resource Observations
1. **Lightweight Baseline Modules**:
   - Phase 3 (Text Classifier) and Phase 6 (Tactic Detector) execute in sub-millisecond to low single-digit millisecond ranges.
   - Phase 4 (Passive URL Scanner) operates purely via regex and string parsing with near-instantaneous execution.
2. **Semantic Similarity Module**:
   - Phase 7 inference dominates pipeline runtime due to transformer embedding generation (`all-MiniLM-L6-v2`) and NumPy dot-product vector search.
3. **End-to-End Orchestration**:
   - The Phase 11 `InvestigationService` coordinates multi-modal inputs, deterministic aggregation, and mock explanation generation efficiently.
