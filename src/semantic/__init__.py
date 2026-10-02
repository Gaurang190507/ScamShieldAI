"""ScamShield AI Phase 7: Semantic Similarity & Novelty Detection package.

Exports:
- Schemas: ReferenceItem, NeighborResult, SemanticAnalysis, SemanticResult
- Embedder: TextEmbedder, save_embedding_cache, load_embedding_cache
- Similarity: compute_cosine_similarity, compute_similarity_1d_to_2d, compute_similarity_matrix
- Index: SemanticReferenceIndex
- Novelty: NoveltyDetector
- Analyzer: SemanticAnalyzer
"""

from .analyzer import SemanticAnalyzer
from .embedder import TextEmbedder, load_embedding_cache, save_embedding_cache
from .novelty import NoveltyDetector
from .reference_index import SemanticReferenceIndex
from .schemas import NeighborResult, ReferenceItem, SemanticAnalysis, SemanticResult
from .similarity import (
    compute_cosine_similarity,
    compute_similarity_1d_to_2d,
    compute_similarity_matrix,
)

__all__ = [
    "SemanticAnalyzer",
    "TextEmbedder",
    "save_embedding_cache",
    "load_embedding_cache",
    "NoveltyDetector",
    "SemanticReferenceIndex",
    "ReferenceItem",
    "NeighborResult",
    "SemanticAnalysis",
    "SemanticResult",
    "compute_cosine_similarity",
    "compute_similarity_1d_to_2d",
    "compute_similarity_matrix",
]
