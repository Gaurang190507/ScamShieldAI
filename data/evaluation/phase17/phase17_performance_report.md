# ScamShield AI — Phase 17 Performance Benchmarking Report

## 1. Executive Summary & Runtime Profile

Phase 17 performance benchmarking evaluates service initialization latency, memory footprint, and steady-state warm inference across all modalities and input types, specifically measuring the latency impact of the Phase 17 normalizers and modality routing.

- **Initialization Latency**: 92.25 ms
- **Warmup Latency (Embedder + Artifacts)**: 6,709.58 ms
- **Post-repair bare URL mean latency**: 7.41 ms (Min: 5.85 ms)
- **Standard Text Evaluation Mean Latency**: 23.45 ms (Min: 21.59 ms)
- **Obfuscated Text Evaluation Mean Latency**: 30.01 ms (Min: 19.38 ms)
- **Memory Footprint**: ~380 MB RSS (constant, leak-free under repeated queries)

---

## 2. Modality & Workload Latency Profile

| Modality / Workload | Phase 17 Measured Latency | Measured Range (Min – Max) | Processing Path Notes |
|---|---|---|---|
| **Bare URL Input** | **7.41 ms** | 5.85 ms – 11.50 ms | Bypasses text classifier & semantic embedding entirely |
| **Standard Clean Text** | **23.45 ms** | 21.59 ms – 41.60 ms | Fast-path embedding cache & baseline classification |
| **Obfuscated Text** | **30.01 ms** | 19.38 ms – 74.10 ms | Includes character-spacing and homoglyph normalization |
| **Missing Native OCR** | **< 1.0 ms** | 0.20 ms – 0.85 ms | Graceful binary detection; returns without unhandled crash |

> [!NOTE]
> **Baseline Latency Audit Note**: Phase 16 recorded an overall multi-modal mean latency of 90.38 ms across its 90 heterogeneous cases, but did not record an isolated bare-URL-specific baseline. To prevent conflation of overall multi-modal latency with bare-URL processing, relative percentage reduction claims against Phase 16 have been removed in favor of direct empirical post-repair measurements.

---

## 3. Overhead Analysis of Phase 17 Repair Layers

### 3.1 Normalization Overhead (`ObfuscationNormalizer`)
- The regex pipeline performs four sequential passes:
  1. Cyrillic homoglyph folding
  2. Defanged URL restoration
  3. Single-character spacing collapse (`\b[A-Za-z](?:\s+[A-Za-z]){2,}\b`)
  4. Punctuation collapse
- **Measured CPU Overhead**: < 0.35 ms per 1,000 characters.
- **Resource Boundary Protection**: If input exceeds `MAX_TEXT_LENGTH = 50,000` characters, input is safely capped at 50,000 with a telemetry diagnostic warning. Adversarial long-input testing completed within the configured resource boundary, with no observed regex-induced resource exhaustion.

### 3.2 Contextual Tactic Enhancer Overhead
- Runs lightweight regex pattern scanners across normalized text.
- **Measured CPU Overhead**: < 0.40 ms.

### 3.3 Emerging Pattern Analyzer Overhead
- Operates on precomputed tactic dictionaries and scalar anomaly scores.
- **Measured CPU Overhead**: < 0.10 ms.

---

## 4. Latency Distribution & Stability

Under 100 consecutive randomized test queries across text, URL, and obfuscated inputs:
- **p50 (Median)**: 21.8 ms
- **p90**: 38.2 ms
- **p95**: 45.6 ms
- **p99**: 74.1 ms
- **Maximum Outlier**: 95.9 ms (first cold-path semantic retrieval)

All measurements conform strictly to production latency budgets (< 150 ms p95 SLA).
