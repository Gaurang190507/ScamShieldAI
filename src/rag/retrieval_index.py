"""Deterministic lexical retrieval index for ScamShield AI Phase 10.

Uses TF-IDF vectorization and cosine similarity over versioned knowledge base chunks.
100% offline, reproducible, and explainable without external vector databases.
"""

from typing import List, Optional, Sequence, Union
import numpy as np
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.metrics.pairwise import cosine_similarity

from .schemas import KnowledgeChunk, RetrievalQuery, RetrievedChunk


class RetrievalIndex:
    """In-memory TF-IDF lexical index indexing knowledge base chunks."""

    def __init__(self, chunks: Optional[Sequence[KnowledgeChunk]] = None):
        """Initializes and builds index over provided chunks."""
        self.chunks: List[KnowledgeChunk] = list(chunks) if chunks is not None else []
        self.vectorizer = TfidfVectorizer(
            stop_words="english",
            ngram_range=(1, 2),
            sublinear_tf=True,
            norm="l2",
        )
        self.tfidf_matrix: Optional[np.ndarray] = None
        self.is_indexed: bool = False

        if self.chunks:
            self.build_index(self.chunks)

    def build_index(self, chunks: Sequence[KnowledgeChunk]) -> "RetrievalIndex":
        """Indexes chunk texts and titles into TF-IDF representation."""
        if not chunks:
            raise ValueError("Cannot build retrieval index on empty chunks list.")

        self.chunks = list(chunks)
        corpus: List[str] = []

        for c in self.chunks:
            # Emphasize title and topic by repeating them in the indexed document representation
            doc_repr = f"{c.title} {c.title} {c.topic} {c.text}"
            corpus.append(doc_repr)

        self.tfidf_matrix = self.vectorizer.fit_transform(corpus)
        self.is_indexed = True
        return self

    def search(
        self,
        query: Union[str, RetrievalQuery],
        top_k: int = 3,
        min_score: float = 0.01,
    ) -> List[RetrievedChunk]:
        """Performs cosine similarity search against indexed knowledge base chunks.

        Args:
            query: Query string or structured RetrievalQuery instance.
            top_k: Maximum number of ranked passages to return.
            min_score: Minimum similarity score threshold.

        Returns:
            Ranked list of RetrievedChunk instances.
        """
        if not self.is_indexed or self.tfidf_matrix is None:
            raise RuntimeError("Retrieval index is not built. Call build_index() first.")

        query_str = query.query_text if isinstance(query, RetrievalQuery) else str(query)
        if not query_str.strip():
            return []

        q_vec = self.vectorizer.transform([query_str])
        sims = cosine_similarity(q_vec, self.tfidf_matrix)[0]

        # Get top-k indices sorted descending
        top_indices = np.argsort(sims)[::-1][:top_k]

        results: List[RetrievedChunk] = []
        for idx in top_indices:
            score = float(sims[idx])
            if score < min_score and len(results) > 0:
                continue
            chunk = self.chunks[idx]
            retrieved = RetrievedChunk(
                document_id=chunk.document_id,
                chunk_id=chunk.chunk_id,
                title=chunk.title,
                source=chunk.source,
                topic=chunk.topic,
                similarity_score=round(score, 4),
                text=chunk.text,
                citation_id=chunk.citation_id,
            )
            results.append(retrieved)

        return results
