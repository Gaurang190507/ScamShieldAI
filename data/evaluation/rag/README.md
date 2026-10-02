# ScamShield AI — Phase 10 Evaluation Artifacts

This directory contains evaluation benchmarks, case specifications, and forensic validation reports
for **Phase 10: RAG + Evidence-Based GenAI Explanation**.

## Evaluation Summary
- **Benchmark size**: 12 cases (Top-K=3)
- **Recall@3**: 83.3% (10/12 benchmark cases, below predefined >=85% target)
- **Precision@3**: 36.1% (topical retrieval precision is an identified limitation of lexical TF-IDF)
- **Source attribution correctness**: 100.0%
- **Irrelevant retrieval rate**: 63.9%
- **Grounding validator pass rate**: 100.0%
- **Decision consistency**: 100.0%
- **Evidence coverage**: 100.0%
- **Citation correctness**: 100.0%
- **Unsupported claims detected by implemented validator**: 0
- **Evaluated prompt-injection cases**: 1
- **Prompt-injection tests passed**: 1/1 (100.0%)

## Files
- `retrieval_cases.jsonl`: 12 diverse evaluation cases (obvious scams, benign, mixed signals, hard negatives, adversarial).
- `explanation_cases.jsonl`: Standardized benchmark inputs for explanation generation.
- `rag_evaluation.md`: Full markdown evaluation report detailing Recall@K, Grounding, and Injection resistance.
- `evaluation_results.json`: Raw structured machine-readable metrics.

## Running the Benchmark
```bash
python -c "from src.rag.evaluate_rag import run_phase10_evaluation; run_phase10_evaluation()"
```