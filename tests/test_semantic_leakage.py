"""Strict leakage prevention and boundary verification for Phase 7 semantic layer.

Verifies:
1. Reference corpus membership is strictly restricted to the Phase 3 TRAIN split (3,881 samples).
2. Zero sample ID overlap between reference corpus and validation partition (837 samples).
3. Zero sample ID overlap between reference corpus and test partition (856 samples).
4. Zero exact text string overlap between reference corpus and validation or test partitions.
5. Zero normalized duplicate text overlap between reference corpus and validation or test partitions.
6. Programmatic guard disallowing query sample ID from existing inside the reference index.
7. Guaranteed absence of self-retrieval.
"""

from pathlib import Path
import unittest
import numpy as np

from src.semantic.reference_index import SemanticReferenceIndex
from src.semantic.split_loader import load_canonical_splits


class TestSemanticLeakage(unittest.TestCase):
    """Leakage verification test suite for Phase 7 reference corpus index."""

    @classmethod
    def setUpClass(cls):
        cls.root_dir = Path(__file__).resolve().parents[1]
        cls.ref_dir = cls.root_dir / "data" / "semantic" / "reference"

        # Load canonical splits
        cls.train_df, cls.val_df, cls.test_df = load_canonical_splits()

        # Load saved reference index
        if not (cls.ref_dir / "reference_items.jsonl").is_file():
            raise FileNotFoundError(
                f"Reference index not found at {cls.ref_dir}. Run `python -m src.semantic --build-index`."
            )
        cls.index = SemanticReferenceIndex.load(cls.ref_dir)

    def test_reference_corpus_size_matches_train_partition(self):
        """Verifies reference index size strictly equals the 3,881 training samples."""
        self.assertEqual(self.index.size, 3881)
        self.assertEqual(len(self.train_df), 3881)

        # Verify all index items originate from train_df
        train_ids = set(self.train_df["sample_id"])
        index_ids = set(self.index.sample_id_to_idx.keys())
        self.assertEqual(index_ids, train_ids)

    def test_zero_sample_id_overlap_with_validation_and_test(self):
        """Verifies reference index has zero sample ID overlap with validation or test sets."""
        ref_ids = set(self.index.sample_id_to_idx.keys())
        val_ids = set(self.val_df["sample_id"])
        test_ids = set(self.test_df["sample_id"])

        self.assertEqual(len(val_ids), 837)
        self.assertEqual(len(test_ids), 856)

        val_overlap = ref_ids.intersection(val_ids)
        test_overlap = ref_ids.intersection(test_ids)

        self.assertEqual(
            len(val_overlap),
            0,
            f"LEAKAGE DETECTED: {len(val_overlap)} validation sample IDs found in reference index!",
        )
        self.assertEqual(
            len(test_overlap),
            0,
            f"LEAKAGE DETECTED: {len(test_overlap)} test sample IDs found in reference index!",
        )

    def test_zero_exact_text_overlap_with_validation_and_test(self):
        """Verifies exact verbatim text never crosses into validation or test partitions."""
        val_texts = set(self.val_df["text"])
        test_texts = set(self.test_df["text"])

        val_exact_overlap = self.index.exact_text_set.intersection(val_texts)
        test_exact_overlap = self.index.exact_text_set.intersection(test_texts)

        self.assertEqual(
            len(val_exact_overlap),
            0,
            f"LEAKAGE DETECTED: {len(val_exact_overlap)} exact texts cross into validation set!",
        )
        self.assertEqual(
            len(test_exact_overlap),
            0,
            f"LEAKAGE DETECTED: {len(test_exact_overlap)} exact texts cross into test set!",
        )

    def test_zero_normalized_text_overlap_with_validation_and_test(self):
        """Verifies normalized duplicate text strings never cross into validation or test partitions."""
        val_norm = set(self.val_df["normalized_text"].astype(str).str.strip().str.lower())
        test_norm = set(self.test_df["normalized_text"].astype(str).str.strip().str.lower())

        val_norm_overlap = self.index.norm_text_set.intersection(val_norm)
        test_norm_overlap = self.index.norm_text_set.intersection(test_norm)

        self.assertEqual(
            len(val_norm_overlap),
            0,
            f"LEAKAGE DETECTED: {len(val_norm_overlap)} normalized texts cross into validation set!",
        )
        self.assertEqual(
            len(test_norm_overlap),
            0,
            f"LEAKAGE DETECTED: {len(test_norm_overlap)} normalized texts cross into test set!",
        )

    def test_guard_prevents_same_sample_query_leakage(self):
        """Verifies that attempting to query with an ID already in reference index raises ValueError."""
        # Pick an arbitrary sample ID from training reference corpus
        train_id = self.train_df.iloc[0]["sample_id"]
        dummy_vec = np.zeros(self.index.dimension, dtype=np.float32)

        with self.assertRaises(ValueError) as ctx:
            self.index.search(dummy_vec, top_k=5, query_sample_id=train_id, disallow_same_id=True)
        self.assertIn("Data leakage violation", str(ctx.exception))

    def test_validation_query_never_retrieves_self(self):
        """Verifies that querying a validation sample returns reference neighbors with disjoint IDs."""
        val_sample = self.val_df.iloc[0]
        val_id = val_sample["sample_id"]
        dummy_vec = np.random.randn(self.index.dimension).astype(np.float32)

        neighbors = self.index.search(
            dummy_vec,
            top_k=5,
            query_sample_id=val_id,
            disallow_same_id=True,
        )

        retrieved_ids = [n.sample_id for n in neighbors]
        self.assertNotIn(val_id, retrieved_ids)
        for rid in retrieved_ids:
            self.assertTrue(self.index.contains_sample_id(rid))


if __name__ == "__main__":
    unittest.main()
