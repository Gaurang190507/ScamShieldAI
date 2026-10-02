# Phase 12: Evaluation Dataset Provenance & Composition Report

## 1. Provenance Registry & Source Mapping
All Phase 12 evaluation samples originate from registered provenance sources logged in `sources.csv`:
- `src_p12_official_advisories`: Official Cybersecurity Advisories (I4C / RBI / CERT-In)
- `src_p12_real_complaints`: Publicly Documented Fraud Reports & Consumer Transcripts
- `src_p12_hard_negatives`: Curated Legitimate High-Urgency & Banking Communications
- `src_p12_multilingual`: Multilingual & Code-Mixed (Hinglish/Hindi) Scam Corpus
- `src_p12_obfuscated`: Controlled Syntactic & Lexical Perturbation Corpus
- `src_p12_novel_patterns`: Emerging & Uncataloged Fraud Patterns (Web3 / AI)
- `src_p12_url_corpus`: Controlled Passive URL Heuristics Benchmark
- `src_p12_screenshots`: Multimodal Screenshot & Image Evaluation Corpus

## 2. Dataset Composition

| Corpus Partition | File Path | Record Count | Ground Truth Labels | Key Threat Focus |
|---|---|---|---|---|
| Modern Indian Scams | `modern_scam_patterns/modern_indian_scams.jsonl` | 20 | 20 scam | Digital arrest, electricity cutoff, UPI scratch, e-challan APK |
| Hard Negatives | `hard_negatives/hard_negatives.jsonl` | 20 | 20 non_scam | 3D-secure OTP, power bill receipt, card alerts, delivery PIN |
| Multilingual | `multilingual/multilingual_cases.jsonl` | 14 | 10 scam, 4 non_scam | Native Devanagari Hindi (5), Romanized Hinglish (9) |
| Controlled Obfuscations | `obfuscated/obfuscated_cases.jsonl` | 10 | 10 scam | Leetspeak, spaced characters, emoji insertion, punctuation |
| Novel Threat Patterns | `novel_patterns/novel_scam_patterns.jsonl` | 10 | 10 scam | Web3 staking yield, AI voice clone, GPU node validator |
| Passive URL Benchmark | `urls/url_benchmark.jsonl` | 24 | 18 suspicious, 6 benign | IP hosts, ports, shorteners, punycode, clean bank portals |
| Screenshot Benchmark | `screenshots/screenshot_cases.jsonl` | 10 | 6 scam, 4 non_scam | OCR text extraction, visual observation verification |
| **Consolidated Text Benchmark** | `real_world/real_world_cases.jsonl` | **74** | **48 scam, 26 non_scam** | Comprehensive real-world text evaluation suite |

## 3. Data Leakage Audit
An automated leakage audit was conducted by `Phase12LeakageAuditor`:
- Exact string overlap against UCI training set (4,459 items): **0**
- Normalized text overlap against UCI training set: **0**
- Exact string overlap against Semantic Reference index (3,790 items): **0**
- Normalized text overlap against Semantic Reference index: **0**
- Hard negative overlap with scam references: **0**
