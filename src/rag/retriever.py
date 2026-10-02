"""High-level Knowledge Retriever service for ScamShield AI Phase 10.

Coordinates:
1. Document loading from versioned storage.
2. Deterministic semantic chunking.
3. TF-IDF lexical index construction.
4. Structured query formulation from Phase 8 case assessment.
5. Auditable passage retrieval.
"""

from pathlib import Path
from typing import List, Optional, Union

from src.aggregation.schemas import CaseAssessmentResult
from .chunker import chunk_all_documents
from .document_loader import load_knowledge_documents
from .query_builder import build_retrieval_query
from .retrieval_index import RetrievalIndex
from .schemas import KnowledgeChunk, KnowledgeDocument, RetrievalQuery, RetrievalResult, RetrievedChunk


class KnowledgeRetriever:
    """End-to-end knowledge base retrieval service."""

    def __init__(
        self,
        kb_dir: Optional[Union[str, Path]] = None,
        documents: Optional[List[KnowledgeDocument]] = None,
        chunks: Optional[List[KnowledgeChunk]] = None,
    ):
        """Initializes retriever and indexes knowledge base."""
        self.kb_dir = kb_dir
        if chunks is not None:
            self.chunks = chunks
            self.documents = documents or []
        else:
            self.documents = documents or load_knowledge_documents(kb_dir=self.kb_dir)
            self.chunks = chunk_all_documents(self.documents)

        self.index = RetrievalIndex(self.chunks)

    def retrieve(
        self,
        case_result: CaseAssessmentResult,
        top_k: int = 3,
    ) -> RetrievalResult:
        """Retrieves top-K authoritative knowledge chunks relevant to a case assessment.

        Args:
            case_result: Phase 8 CaseAssessmentResult instance.
            top_k: Number of relevant passages to retrieve. Defaults to 3.

        Returns:
            RetrievalResult containing query, ranked chunks, and audit metadata.
        """
        query = build_retrieval_query(case_result=case_result)
        ranked_chunks = self.index.search(query=query, top_k=top_k)

        return RetrievalResult(
            query=query,
            retrieved_chunks=ranked_chunks,
            retrieval_method="tfidf_cosine",
            top_k=top_k,
            total_indexed_chunks=len(self.chunks),
        )

    def retrieve_by_query(
        self,
        query_text: str,
        top_k: int = 3,
    ) -> RetrievalResult:
        """Direct retrieval interface given a query string."""
        query = build_retrieval_query(override_query_text=query_text)
        ranked_chunks = self.index.search(query=query, top_k=top_k)

        return RetrievalResult(
            query=query,
            retrieved_chunks=ranked_chunks,
            retrieval_method="tfidf_cosine",
            top_k=top_k,
            total_indexed_chunks=len(self.chunks),
        )
