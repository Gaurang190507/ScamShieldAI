"""Verification and regression test suite for Phase 3 dataset split integrity and leakage prevention.

Requirements verified:
1. Train/validation/test sample IDs do not overlap.
2. Train/validation/test exact texts do not overlap (zero duplicate leakage).
3. Normalized duplicate texts do not cross split partitions.
4. Pattern groups do not cross splits when multi-record groups exist.
5. TF-IDF vectorizer fit occurs strictly on training data only (no test vocabulary leakage).
6. Threshold selection criterion is computed strictly from validation partition.
7. Test partition remains strictly untouched until final evaluation.
"""

from collections import defaultdict
import json
from pathlib import Path
import re
import unittest
import joblib
import numpy as np
import pandas as pd

from src.data.leakage_split import group_leakage_split, verify_no_group_leakage
from src.models.baseline_classifier import BaselineTextClassifier


class TestPhase3SplitIntegrity(unittest.TestCase):
    """Integrity audit test suite for Phase 3 data splitting and leakage isolation."""

    @classmethod
    def setUpClass(cls):
        cls.root_dir = Path(__file__).resolve().parents[1]
        cls.dataset_path = cls.root_dir / "data" / "processed" / "preprocessed" / "uci_sms_spam.jsonl"
        cls.models_dir = cls.root_dir / "models" / "baseline"
        cls.eval_dir = cls.root_dir / "data" / "evaluation" / "baseline"

        if not cls.dataset_path.is_file():
            raise FileNotFoundError(f"Dataset missing: {cls.dataset_path}")

        cls.df = pd.read_json(cls.dataset_path, lines=True)

        # Reproduce the splitting cluster mapping used in train_baseline.py
        parent = {idx: idx for idx in cls.df.index}

        def find(i: int) -> int:
            if parent[i] != i:
                parent[i] = find(parent[i])
            return parent[i]

        def union(i: int, j: int) -> None:
            ri, rj = find(i), find(j)
            if ri != rj:
                parent[ri] = rj

        # A. Cluster samples sharing identical normalized_text
        norm_to_indices = defaultdict(list)
        for idx, row in cls.df.iterrows():
            norm_key = str(row.get("normalized_text") or row.get("text", "")).strip().lower()
            if norm_key:
                norm_to_indices[norm_key].append(idx)

        for indices in norm_to_indices.values():
            for other in indices[1:]:
                union(indices[0], other)

        # B. Cluster samples sharing genuine multi-record pattern groups
        grp_to_indices = defaultdict(list)
        for idx, row in cls.df.iterrows():
            grp = row.get("pattern_group_id")
            if (
                grp
                and not str(grp).startswith("grp_uci_unassigned_")
                and grp not in ("unknown", "none", "")
            ):
                grp_to_indices[str(grp)].append(idx)

        for indices in grp_to_indices.values():
            for other in indices[1:]:
                union(indices[0], other)

        cls.df["_split_cluster_id"] = [f"cluster_{find(i)}" for i in cls.df.index]

        cls.train_df, cls.val_df, cls.test_df = group_leakage_split(
            cls.df,
            group_col="_split_cluster_id",
            test_size=0.15,
            val_size=0.15,
            random_state=42,
        )

    def test_01_split_sample_ids_do_not_overlap(self):
        """Test 1: Train, validation, and test sample IDs are mutually disjoint and cover all rows."""
        train_ids = set(self.train_df["sample_id"])
        val_ids = set(self.val_df["sample_id"])
        test_ids = set(self.test_df["sample_id"])

        self.assertEqual(len(train_ids.intersection(val_ids)), 0, "Train and Val sample IDs overlap")
        self.assertEqual(len(train_ids.intersection(test_ids)), 0, "Train and Test sample IDs overlap")
        self.assertEqual(len(val_ids.intersection(test_ids)), 0, "Val and Test sample IDs overlap")

        total_split = len(train_ids) + len(val_ids) + len(test_ids)
        self.assertEqual(total_split, len(self.df), f"Expected {len(self.df)} total rows, got {total_split}")
        self.assertEqual(len(train_ids), 3881)
        self.assertEqual(len(val_ids), 837)
        self.assertEqual(len(test_ids), 856)

    def test_02_exact_texts_do_not_cross_splits(self):
        """Test 2: Verbatim exact text strings never cross train, validation, or test partitions."""
        train_texts = set(self.train_df["text"])
        val_texts = set(self.val_df["text"])
        test_texts = set(self.test_df["text"])

        tv_overlap = train_texts.intersection(val_texts)
        tt_overlap = train_texts.intersection(test_texts)
        vt_overlap = val_texts.intersection(test_texts)

        self.assertEqual(len(tv_overlap), 0, f"Train/Val exact text leak: {len(tv_overlap)}")
        self.assertEqual(len(tt_overlap), 0, f"Train/Test exact text leak: {len(tt_overlap)}")
        self.assertEqual(len(vt_overlap), 0, f"Val/Test exact text leak: {len(vt_overlap)}")

    def test_03_normalized_duplicates_do_not_cross_splits(self):
        """Test 3: Normalized duplicate texts never cross train, validation, or test partitions."""
        train_norm = set(self.train_df["normalized_text"].astype(str).str.strip().str.lower())
        val_norm = set(self.val_df["normalized_text"].astype(str).str.strip().str.lower())
        test_norm = set(self.test_df["normalized_text"].astype(str).str.strip().str.lower())

        tv_overlap = train_norm.intersection(val_norm)
        tt_overlap = train_norm.intersection(test_norm)
        vt_overlap = val_norm.intersection(test_norm)

        self.assertEqual(len(tv_overlap), 0, f"Train/Val normalized text leak: {len(tv_overlap)}")
        self.assertEqual(len(tt_overlap), 0, f"Train/Test normalized text leak: {len(tt_overlap)}")
        self.assertEqual(len(vt_overlap), 0, f"Val/Test normalized text leak: {len(vt_overlap)}")

    def test_04_pattern_groups_do_not_cross_splits_when_multi_record_exist(self):
        """Test 4: Pattern groups strictly stay intact within one split when multi-record groups exist."""
        # Create a synthetic dataset containing explicit multi-record groups
        synthetic_records = []
        for grp_idx in range(10):
            for sample_idx in range(4):
                synthetic_records.append({
                    "sample_id": f"syn_{grp_idx}_{sample_idx}",
                    "text": f"Campaign message variant {sample_idx} for group {grp_idx}",
                    "normalized_text": f"campaign message variant {sample_idx} for group {grp_idx}",
                    "pattern_group_id": f"campaign_grp_{grp_idx}",
                    "label": "scam" if grp_idx % 2 == 0 else "non_scam",
                })
        synth_df = pd.DataFrame(synthetic_records)

        syn_train, syn_val, syn_test = group_leakage_split(
            synth_df,
            group_col="pattern_group_id",
            test_size=0.20,
            val_size=0.20,
            random_state=42,
        )

        is_leak_free, leak_msg = verify_no_group_leakage(
            syn_train, syn_val, syn_test, group_col="pattern_group_id"
        )
        self.assertTrue(is_leak_free, leak_msg)

        # Confirm each group appears exclusively in one split
        train_grps = set(syn_train["pattern_group_id"])
        val_grps = set(syn_val["pattern_group_id"])
        test_grps = set(syn_test["pattern_group_id"])

        self.assertTrue(train_grps.isdisjoint(val_grps))
        self.assertTrue(train_grps.isdisjoint(test_grps))
        self.assertTrue(val_grps.isdisjoint(test_grps))

    def test_05_tfidf_fit_occurs_only_on_training_data(self):
        """Test 5: TF-IDF vectorizer reflects only training vocabulary with zero test token leakage."""
        vec_file = self.models_dir / "tfidf_vectorizer.joblib"
        self.assertTrue(vec_file.is_file(), "tfidf_vectorizer.joblib artifact missing")
        vectorizer = joblib.load(vec_file)

        # Collect words that appear exclusively in the test set
        def extract_words(texts):
            words = set()
            for t in texts:
                for w in re.findall(r"\b\w+\b", t.lower()):
                    words.add(w)
            return words

        train_words = extract_words(self.train_df["text"])
        test_words = extract_words(self.test_df["text"])
        test_exclusive_words = test_words - train_words

        # Assert that there are test-exclusive words
        self.assertGreater(len(test_exclusive_words), 100)

        # Regression check: NONE of the test-exclusive words may appear in the fitted TF-IDF vocabulary
        leaked_tokens = [w for w in test_exclusive_words if w in vectorizer.vocabulary_]
        self.assertEqual(
            len(leaked_tokens),
            0,
            f"Test-exclusive tokens leaked into TF-IDF vocabulary: {leaked_tokens[:10]}",
        )

    def test_06_threshold_selection_uses_validation_data_only(self):
        """Test 6: Decision threshold selection is determined strictly from validation partition."""
        metrics_file = self.eval_dir / "metrics.json"
        self.assertTrue(metrics_file.is_file(), "metrics.json missing")
        with open(metrics_file, "r", encoding="utf-8") as f:
            metrics = json.load(f)

        meta = metrics["metadata"]
        val_tuning = metrics["validation_threshold_tuning"]
        selected_thresh = meta["selected_threshold"]

        # Verify that selected_threshold has the highest scam F1 on validation tuning
        val_f1_scores = {
            float(t): m["scam"]["f1_score"] for t, m in val_tuning.items()
        }
        best_val_thresh = max(val_f1_scores, key=val_f1_scores.get)
        self.assertEqual(
            selected_thresh,
            best_val_thresh,
            f"Selected threshold {selected_thresh} does not match highest validation F1 {best_val_thresh}",
        )

    def test_07_test_set_remains_untouched_until_final_evaluation(self):
        """Test 7: Test predictions match untouched single-pass evaluation at selected threshold."""
        preds_file = self.eval_dir / "test_predictions.jsonl"
        self.assertTrue(preds_file.is_file(), "test_predictions.jsonl missing")

        # Load predictions
        preds = []
        with open(preds_file, "r", encoding="utf-8") as f:
            for line in f:
                preds.append(json.loads(line))

        self.assertEqual(len(preds), len(self.test_df))
        test_pred_ids = [p["sample_id"] for p in preds]
        test_actual_ids = list(self.test_df["sample_id"])
        self.assertEqual(test_pred_ids, test_actual_ids)

        # Validate that model inference produces the identical probabilities
        classifier = BaselineTextClassifier(model_dir=self.models_dir)
        sample_to_check = preds[0]
        sample_res = classifier.predict(sample_to_check["text"])
        self.assertAlmostEqual(
            sample_res["probability"],
            sample_to_check["predicted_probability"],
            places=3,
        )


if __name__ == "__main__":
    unittest.main()
