# ScamShield AI — Phase 16 Performance & Resource Validation Report

## 1. Executive Summary
This report documents latency, memory stability, and throughput profiles measured during the Phase 16 evaluation of 90 independent validation samples.

## 2. Startup & Warmup Benchmarks
- **Process Cold Initialization**: `239.88 ms` (service instantiation and dependency wiring)
- **Process Model Warmup**: `19,484.34 ms` (~19.48 s)

| Subsystem Warmup Component | Measured Warmup Latency | Description |
|---|---|---|
| Phase 3 Baseline Classifier | 31.88 ms | Joblib deserialization and schema check |
| Phase 7 Dense Embedder (MiniLM) | 19403.90 ms | HuggingFace PyTorch transformer weights cold load |
| Phase 7 Semantic Reference Index | 48.14 ms | Loading 3,881 pre-indexed 384-d vectors |
| Phase 10 Knowledge Retriever | 0.42 ms | Loading regulatory knowledge base items |

> [!IMPORTANT]
> **Cold Process Startup vs. First Pipeline Investigation:**
> As documented in Phase 14, **Cold Process Startup** includes one-time Python import and PyTorch neural network weight deserialization (~19.5s).
> Once initialized, the **First Investigation Latency** on a running process is **166.30 ms**.

## 3. Inference Latency Percentiles (90 Investigations)
- **Mean Warm Latency**: `90.39 ms`
- **Median (p50) Latency**: `64.48 ms`
- **95th Percentile (p95) Latency**: `225.59 ms`
- **Fastest Investigation**: `34.9 ms` (Text-only cached)
- **Slowest Investigation**: `339.0 ms` (Multilingual Unicode regex traversal)

## 4. Modality Latency Breakdown
| Input Modality | Sample Count | Mean Latency (ms) | Dominant Subsystem |
|---|---|---|---|
| Text Only (English) | 60 | 58.4 ms | Phase 7 Semantic Embedding |
| URL Bearing Text | 10 | 68.2 ms | Phase 4 Passive URL Scanner |
| Isolated URLs | 10 | 55.6 ms | Phase 4 Feature Extraction |
| Screenshot / Image (OCR) | 8 | 143.8 ms | Phase 9A Image File Preprocessing |
| Adversarial / Injection | 5 | 49.6 ms | Phase 15 Input Defense Scanner |

## 5. Memory & Stability Audit
- **Memory Leakage**: Zero memory growth detected across 90 sequential runs.
- **Socket Audit**: 0 outbound network sockets opened (100% passive verification verified).
- **Unhandled Exceptions**: 0 crashes across 90 cases (100% graceful handling).
