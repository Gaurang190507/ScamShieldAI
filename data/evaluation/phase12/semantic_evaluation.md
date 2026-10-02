# Phase 12: Phase 7 Semantic Similarity & Novelty Evaluation

## 1. Overview
Phase 7 evaluates semantic embeddings (`all-MiniLM-L6-v2`) against the frozen reference corpus (`data/semantic/reference/reference_items.jsonl`, 3,790 training samples) without making network calls.

## 2. Partition Similarity & Novelty Metrics

| Partition | Samples | Mean Top-1 Sim | Median Top-1 Sim | Mean Novelty Score | Semantic Status Distribution |
|---|---|---|---|---|---|
| Modern Indian Scams | 20 | 0.4451 | 0.4407 | 0.5549 | potentially_novel: 17, moderately_novel: 3 |
| Hard Negatives | 20 | 0.4348 | 0.4141 | 0.5652 | potentially_novel: 19, moderately_novel: 1 |
| Novel Threat Patterns | 10 | 0.3567 | 0.3374 | 0.6433 | potentially_novel: 9, moderately_novel: 1 |
| Multilingual | 14 | 0.4861 | 0.4867 | 0.5139 | potentially_novel: 9, moderately_novel: 5 |
| Controlled Obfuscations | 10 | 0.5139 | 0.4996 | 0.4861 | moderately_novel: 4, potentially_novel: 5, similar_to_known: 1 |

## 3. Analysis of Semantic Novelty Scoring
- **Scope Distinction**: The semantic subsystem can identify low-similarity cases relative to its reference corpus, but low similarity does not itself establish that a case is a genuinely novel scam.
- **Novel Threat Patterns**: Exhibits higher novelty scores and lower top-1 similarity against historical UCI templates, properly categorizing novel patterns as `potentially_novel` or `moderately_novel`.
- **Modern Indian Scams**: While distinct in local phrasing, share semantic proximity with financial and urgency templates in the reference corpus.
- **Multilingual Gaps**: Devanagari Hindi text yields low cosine similarity against the predominantly English reference index, registering as novel patterns due to language distance rather than threat novelty per se.
