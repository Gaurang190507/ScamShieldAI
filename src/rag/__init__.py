"""ScamShield AI — Phase 10 Knowledge Retrieval & RAG Module.

Provides versioned document ingestion, deterministic semantic chunking,
TF-IDF lexical indexing, provenance citation tracking, and structured query generation.
"""

from .chunker import chunk_all_documents, chunk_document
from .citations import (
    extract_citations,
    format_case_citation,
    format_kb_citation,
    validate_citations,
)
from .document_loader import load_knowledge_documents
from .query_builder import build_retrieval_query
from .retrieval_index import RetrievalIndex
from .retriever import KnowledgeRetriever
from .schemas import (
    KnowledgeChunk,
    KnowledgeDocument,
    RetrievalQuery,
    RetrievalResult,
    RetrievedChunk,
)

__all__ = [
    "KnowledgeDocument",
    "KnowledgeChunk",
    "RetrievalQuery",
    "RetrievedChunk",
    "RetrievalResult",
    "load_knowledge_documents",
    "chunk_document",
    "chunk_all_documents",
    "format_case_citation",
    "format_kb_citation",
    "extract_citations",
    "validate_citations",
    "build_retrieval_query",
    "RetrievalIndex",
    "KnowledgeRetriever",
]
