"""Unit tests for ScamShield AI Phase 10 Knowledge Base loading, chunking, and retrieval."""

from pathlib import Path
import unittest

from src.rag.chunker import chunk_all_documents, chunk_document
from src.rag.document_loader import load_knowledge_documents
from src.rag.query_builder import build_retrieval_query
from src.rag.retrieval_index import RetrievalIndex
from src.rag.retriever import KnowledgeRetriever
from src.rag.schemas import KnowledgeDocument, RetrievalQuery


class TestRAGRetrieval(unittest.TestCase):
    """Verifies document loading, semantic chunking, and deterministic lexical retrieval."""

    def setUp(self):
        self.kb_dir = Path("data/knowledge_base")
        self.assertTrue(self.kb_dir.is_dir(), "Knowledge base directory must exist.")

    def test_load_knowledge_documents(self):
        """All documents in data/knowledge_base/ must load with complete required metadata."""
        docs = load_knowledge_documents(self.kb_dir)
        self.assertGreaterEqual(len(docs), 8)

        for d in docs:
            self.assertIsInstance(d, KnowledgeDocument)
            self.assertTrue(d.document_id.startswith("doc_"))
            self.assertTrue(len(d.title) > 0)
            self.assertTrue(len(d.source) > 0)
            self.assertIn(d.source_type, ["official_knowledge", "official_advisory", "security_guidance"])
            self.assertTrue(len(d.content) > 50)
            self.assertIn(d.jurisdiction, ["IN", "Global"])

    def test_chunking_preserves_metadata_and_boundaries(self):
        """Chunking must preserve document provenance and generate valid citation IDs."""
        docs = load_knowledge_documents(self.kb_dir)
        all_chunks = chunk_all_documents(docs)

        self.assertGreaterEqual(len(all_chunks), len(docs))
        for c in all_chunks:
            self.assertTrue(c.chunk_id.startswith("chunk_"))
            self.assertTrue(c.document_id.startswith("doc_"))
            self.assertEqual(c.citation_id, f"[KB:{c.document_id}:{c.chunk_id}]")
            self.assertGreater(c.word_count, 0)
            self.assertTrue(len(c.text) > 0)

    def test_retrieval_index_search_determinism(self):
        """TF-IDF retrieval index returns top-K results sorted by similarity score."""
        docs = load_knowledge_documents(self.kb_dir)
        chunks = chunk_all_documents(docs)
        index = RetrievalIndex(chunks)

        results = index.search("digital arrest cbi police video call money transfer", top_k=3)
        self.assertEqual(len(results), 3)

        # First result should match authority impersonation or I4C
        top_res = results[0]
        self.assertIn(top_res.document_id, ["doc_impersonation_authority", "doc_i4c_citizen_guidelines"])
        self.assertGreater(top_res.similarity_score, 0.0)
        self.assertTrue(top_res.citation_id.startswith("[KB:"))

        # Determinism check
        repeat = index.search("digital arrest cbi police video call money transfer", top_k=3)
        self.assertEqual([r.chunk_id for r in results], [r.chunk_id for r in repeat])
        self.assertEqual([r.similarity_score for r in results], [r.similarity_score for r in repeat])

    def test_retrieval_query_builder_fallbacks(self):
        """Query builder provides robust defaults when signals are absent."""
        q = build_retrieval_query()
        self.assertIsInstance(q, RetrievalQuery)
        self.assertGreater(len(q.query_text), 0)

        q_custom = build_retrieval_query(override_query_text="sms phishing lottery refund")
        self.assertEqual(q_custom.query_text, "sms phishing lottery refund")

    def test_retriever_service_end_to_end(self):
        """KnowledgeRetriever coordinates end-to-end retrieval with structured result."""
        retriever = KnowledgeRetriever(self.kb_dir)
        res = retriever.retrieve_by_query("scan QR code in PhonePe UPI receive refund", top_k=2)

        self.assertEqual(res.retrieval_method, "tfidf_cosine")
        self.assertEqual(res.top_k, 2)
        self.assertEqual(len(res.retrieved_chunks), 2)
        self.assertIn("doc_payment_qr_fraud", [c.document_id for c in res.retrieved_chunks])


if __name__ == "__main__":
    unittest.main()
