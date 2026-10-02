"""Canonical data schemas for ScamShield AI Phase 7 semantic similarity and novelty detection.

Defines structured objects for:
- ReferenceItem: Metadata and text for a reference corpus sample.
- NeighborResult: Retrieved nearest-neighbor reference example.
- SemanticAnalysis: Quantitative semantic retrieval and novelty metrics.
- SemanticResult: Complete structured response container for a query.
"""

from dataclasses import asdict, dataclass, field
from typing import Any, Dict, List, Optional


@dataclass
class ReferenceItem:
    """Represents a sample stored in the known reference index."""

    sample_id: str
    label: str  # "scam" or "non_scam"
    text: str
    text_preview: str
    source: str
    pattern_group_id: Optional[str] = None
    embedding_idx: int = 0

    def to_dict(self) -> Dict[str, Any]:
        """Serializes reference item to dictionary."""
        return asdict(self)


@dataclass
class NeighborResult:
    """Represents a retrieved nearest neighbor from the reference corpus."""

    sample_id: str
    similarity: float
    label: str
    source: str
    text_preview: str

    def to_dict(self) -> Dict[str, Any]:
        """Serializes neighbor result to dictionary."""
        return {
            "sample_id": self.sample_id,
            "similarity": round(float(self.similarity), 4),
            "label": self.label,
            "source": self.source,
            "text_preview": self.text_preview,
        }


@dataclass
class SemanticAnalysis:
    """Aggregated semantic similarity and novelty analysis for an input query."""

    embedding_model: str
    embedding_dimension: int
    top_k: int
    top_1_similarity: float
    top_3_max_similarity: float
    top_5_max_similarity: float
    top_5_mean_similarity: float
    top_5_scam_count: int
    top_5_non_scam_count: int
    nearest_scam_similarity: Optional[float]
    nearest_non_scam_similarity: Optional[float]
    semantic_novelty_score: float
    semantic_status: str  # "similar_to_known", "moderately_novel", "potentially_novel"

    def to_dict(self) -> Dict[str, Any]:
        """Serializes semantic metrics to dictionary."""
        return {
            "embedding_model": self.embedding_model,
            "embedding_dimension": self.embedding_dimension,
            "top_k": self.top_k,
            "top_1_similarity": round(float(self.top_1_similarity), 4),
            "top_3_max_similarity": round(float(self.top_3_max_similarity), 4),
            "top_5_max_similarity": round(float(self.top_5_max_similarity), 4),
            "top_5_mean_similarity": round(float(self.top_5_mean_similarity), 4),
            "top_5_scam_count": int(self.top_5_scam_count),
            "top_5_non_scam_count": int(self.top_5_non_scam_count),
            "nearest_scam_similarity": (
                round(float(self.nearest_scam_similarity), 4)
                if self.nearest_scam_similarity is not None
                else None
            ),
            "nearest_non_scam_similarity": (
                round(float(self.nearest_non_scam_similarity), 4)
                if self.nearest_non_scam_similarity is not None
                else None
            ),
            "semantic_novelty_score": round(float(self.semantic_novelty_score), 4),
            "semantic_status": self.semantic_status,
        }


@dataclass
class SemanticResult:
    """Unified container for full semantic retrieval and novelty output."""

    text: str
    semantic: SemanticAnalysis
    neighbors: List[NeighborResult] = field(default_factory=list)
    sample_id: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        """Serializes full semantic analysis result to structured JSON dictionary."""
        return {
            "sample_id": self.sample_id,
            "text": self.text,
            "semantic": self.semantic.to_dict(),
            "neighbors": [n.to_dict() for n in self.neighbors],
        }
