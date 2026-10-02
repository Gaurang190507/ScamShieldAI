"""Canonical data schemas for ScamShield AI Phase 10 RAG & Knowledge Retrieval.

Defines structured representations for:
- KnowledgeDocument: Raw document loaded from the versioned knowledge base.
- KnowledgeChunk: Granular passage preserving provenance and metadata.
- RetrievalQuery: Structured query representation constructed from deterministic findings.
- RetrievedChunk: Retrieved passage enriched with similarity score and citation ID.
- RetrievalResult: Complete auditable retrieval output bundle.
"""

from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional


@dataclass
class KnowledgeDocument:
    """Represents an authoritative reference document in the ScamShield knowledge base."""

    document_id: str
    title: str
    source: str
    source_type: str  # "official_knowledge", "official_advisory", "security_guidance"
    publication_date: str
    retrieval_date: str
    jurisdiction: str
    topic: str
    license_status: str
    content: str
    tags: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        """Serializes document to dictionary."""
        return asdict(self)


@dataclass
class KnowledgeChunk:
    """Granular passage extracted from a KnowledgeDocument."""

    chunk_id: str
    document_id: str
    title: str
    source: str
    topic: str
    text: str
    chunk_index: int
    word_count: int
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        """Serializes chunk to dictionary."""
        return asdict(self)

    @property
    def citation_id(self) -> str:
        """Returns standard citation identifier [KB:doc_id:chunk_id]."""
        return f"[KB:{self.document_id}:{self.chunk_id}]"


@dataclass
class RetrievalQuery:
    """Structured query constructed from deterministic case evidence."""

    query_text: str
    detected_tactics: List[str] = field(default_factory=list)
    requested_actions: List[str] = field(default_factory=list)
    target_assets: List[str] = field(default_factory=list)
    url_findings: List[str] = field(default_factory=list)
    visual_findings: List[str] = field(default_factory=list)
    extracted_keywords: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        """Serializes retrieval query to dictionary."""
        return asdict(self)


@dataclass
class RetrievedChunk:
    """A knowledge chunk retrieved for a specific case with similarity score."""

    document_id: str
    chunk_id: str
    title: str
    source: str
    topic: str
    similarity_score: float
    text: str
    citation_id: str

    def to_dict(self) -> Dict[str, Any]:
        """Serializes retrieved chunk to dictionary."""
        return {
            "document_id": self.document_id,
            "chunk_id": self.chunk_id,
            "title": self.title,
            "source": self.source,
            "topic": self.topic,
            "similarity_score": round(self.similarity_score, 4),
            "citation_id": self.citation_id,
            "text": self.text,
        }


@dataclass
class RetrievalResult:
    """Complete auditable output bundle from the knowledge retrieval step."""

    query: RetrievalQuery
    retrieved_chunks: List[RetrievedChunk]
    retrieval_method: str  # "tfidf_cosine"
    top_k: int
    total_indexed_chunks: int
    timestamp: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )

    def to_dict(self) -> Dict[str, Any]:
        """Serializes retrieval result to dictionary."""
        return {
            "query": self.query.to_dict(),
            "retrieved_chunks": [c.to_dict() for c in self.retrieved_chunks],
            "retrieval_method": self.retrieval_method,
            "top_k": self.top_k,
            "total_indexed_chunks": self.total_indexed_chunks,
            "timestamp": self.timestamp,
        }
