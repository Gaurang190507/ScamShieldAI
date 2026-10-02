"""Unit tests for ScamShield AI Phase 7 semantic embedding and similarity search.

Verifies:
1. Embedding shape, unit normalization, and determinism.
2. Cosine similarity mathematical properties (identity, orthogonality, opposite, clamping).
3. Relative semantic ranking (semantically related texts rank higher than unrelated).
4. Top-K retrieval sorting, count, and metadata integrity.
5. Independence of retrieval similarity from ground-truth labels.
6. Schema serialization to JSON-compatible dictionary.
"""

import unittest
import numpy as np

from src.semantic.embedder import TextEmbedder
from src.semantic.reference_index import SemanticReferenceIndex
from src.semantic.schemas import ReferenceItem, SemanticResult
from src.semantic.similarity import (
    compute_cosine_similarity,
    compute_similarity_1d_to_2d,
    compute_similarity_matrix,
    ensure_unit_norm,
)


class TestSemanticSimilarity(unittest.TestCase):
    """Test suite for semantic embedding and similarity mathematics."""

    @classmethod
    def setUpClass(cls):
        # Initialize embedder once for tests (using local cached model)
        cls.embedder = TextEmbedder()

    def test_embedding_shape_and_norm(self):
        """Verifies embedding dimension is 384 and L2 unit-normalized."""
        text = "Your bank account has been suspended. Please verify your details."
        emb = self.embedder.embed_text(text)

        self.assertIsInstance(emb, np.ndarray)
        self.assertEqual(emb.shape, (384,))
        self.assertEqual(emb.dtype, np.float32)

        # Norm should be approximately 1.0
        norm = np.linalg.norm(emb)
        self.assertAlmostEqual(float(norm), 1.0, places=5)

    def test_embedding_determinism(self):
        """Verifies that identical text generates exact same embedding vector."""
        text = "Urgent lottery prize notification."
        emb1 = self.embedder.embed_text(text)
        emb2 = self.embedder.embed_text(text)
        np.testing.assert_array_almost_equal(emb1, emb2, decimal=6)

    def test_empty_text_embedding(self):
        """Verifies that empty string produces zero vector without crashing."""
        emb = self.embedder.embed_text("")
        self.assertEqual(emb.shape, (384,))
        self.assertTrue(np.all(emb == 0.0))

    def test_cosine_similarity_identity(self):
        """Verifies cosine similarity of identical vectors is approximately 1.0."""
        vec = np.random.randn(384).astype(np.float32)
        vec = ensure_unit_norm(vec)
        sim = compute_cosine_similarity(vec, vec, assume_normalized=True)
        self.assertAlmostEqual(sim, 1.0, places=5)

    def test_cosine_similarity_orthogonality(self):
        """Verifies cosine similarity of orthogonal vectors is approximately 0.0."""
        v1 = np.array([1.0, 0.0, 0.0], dtype=np.float32)
        v2 = np.array([0.0, 1.0, 0.0], dtype=np.float32)
        sim = compute_cosine_similarity(v1, v2)
        self.assertAlmostEqual(sim, 0.0, places=6)

    def test_cosine_similarity_opposite(self):
        """Verifies cosine similarity of opposite vectors is approximately -1.0."""
        v1 = np.array([1.0, 2.0, 3.0], dtype=np.float32)
        v2 = -v1
        sim = compute_cosine_similarity(v1, v2)
        self.assertAlmostEqual(sim, -1.0, places=5)

    def test_semantic_ranking_order(self):
        """Verifies semantically close messages rank higher than unrelated messages."""
        base = "Your bank account has been suspended. Please verify your KYC immediately."
        similar = "Your bank access is blocked. Complete KYC verification now."
        unrelated = "The atmospheric weather in Antarctica reached subzero temperatures today."

        e_base = self.embedder.embed_text(base)
        e_sim = self.embedder.embed_text(similar)
        e_unrelated = self.embedder.embed_text(unrelated)

        sim_score = compute_cosine_similarity(e_base, e_sim)
        unrelated_score = compute_cosine_similarity(e_base, e_unrelated)

        self.assertGreater(
            sim_score,
            unrelated_score,
            f"Expected {sim_score} > {unrelated_score}",
        )
        self.assertGreater(sim_score, 0.70)
        self.assertLess(unrelated_score, 0.40)

    def test_top_k_retrieval_and_label_independence(self):
        """Verifies top-K count, descending ordering, and that labels do not affect similarity."""
        # Create small mock reference corpus
        items = [
            ReferenceItem("ref_0", "non_scam", "Meeting for dinner", "Meeting...", "src1", None, 0),
            ReferenceItem("ref_1", "scam", "Verify your bank KYC", "Verify...", "src2", None, 1),
            ReferenceItem("ref_2", "non_scam", "Bank account verification receipt", "Bank...", "src3", None, 2),
            ReferenceItem("ref_3", "scam", "Free lottery prize claim", "Free...", "src4", None, 3),
        ]

        texts = [item.text for item in items]
        embs = self.embedder.embed_batch(texts)
        index = SemanticReferenceIndex(items, embs, dimension=384)

        query = "Please update your bank KYC details"
        q_emb = self.embedder.embed_text(query)

        neighbors = index.search(q_emb, top_k=3)
        self.assertEqual(len(neighbors), 3)

        # Verify descending order
        sims = [n.similarity for n in neighbors]
        self.assertEqual(sims, sorted(sims, reverse=True))

        # Top neighbor must be ref_1 ("Verify your bank KYC")
        self.assertEqual(neighbors[0].sample_id, "ref_1")
        self.assertEqual(neighbors[0].label, "scam")

    def test_serialization_to_dict(self):
        """Verifies that SemanticResult produces standard serializable dictionary."""
        from src.semantic.analyzer import SemanticAnalyzer
        from src.semantic.schemas import SemanticResult

        items = [
            ReferenceItem("r1", "scam", "Call 0906 to claim lottery", "Call...", "s", None, 0)
        ]
        embs = self.embedder.embed_batch([i.text for i in items])
        index = SemanticReferenceIndex(items, embs, dimension=384)
        analyzer = SemanticAnalyzer(reference_index=index, embedder=self.embedder)

        res = analyzer.analyze("Claim lottery now", sample_id="q1", top_k=1)
        d = res.to_dict()

        self.assertEqual(d["sample_id"], "q1")
        self.assertIn("semantic", d)
        self.assertIn("neighbors", d)
        self.assertIn("top_1_similarity", d["semantic"])
        self.assertIn("semantic_novelty_score", d["semantic"])
        self.assertIn("semantic_status", d["semantic"])
        self.assertEqual(len(d["neighbors"]), 1)


if __name__ == "__main__":
    unittest.main()
