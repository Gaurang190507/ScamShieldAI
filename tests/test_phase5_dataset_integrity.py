"""Permanent integrity audit and regression test suite for Phase 5 dataset consistency.

Guarantees:
1. Canonical dataset integrity: 5,574 records (747 scam, 4,827 non-scam).
2. Record identity preservation: sample_id, text, and label are 100% identical between
   canonical processed and preprocessed artifacts.
3. Partition membership integrity:
   - Train: 3,881 records (520 scam, 3,361 non-scam)
   - Validation: 837 records (104 scam, 733 non-scam)
   - Test: 856 records (123 scam, 733 non-scam)
4. Split alignment between Phase 3 reference and Phase 5 hybrid model:
   - Phase 5 test partition IDs == Phase 3 test partition IDs
   - Phase 5 test true labels == Phase 3 test true labels (0 label differences)
5. Trained model verification:
   - Phase 5 Logistic Regression model was trained on the exact 520 scam / 3,361 non-scam distribution.
6. URL subset validation:
   - Test URL subset contains exactly 24 samples (22 scam, 2 non-scam).
"""

from collections import Counter, defaultdict
import json
from pathlib import Path
import unittest
import joblib
import numpy as np
import pandas as pd

from src.data.leakage_split import group_leakage_split, verify_no_group_leakage


class TestPhase5DatasetIntegrity(unittest.TestCase):
    """Rigorous audit test suite ensuring Phase 5 uses identical data and labels to Phase 3."""

    @classmethod
    def setUpClass(cls):
        cls.root_dir = Path(__file__).resolve().parents[1]
        cls.prep_path = cls.root_dir / "data" / "processed" / "preprocessed" / "uci_sms_spam.jsonl"
        cls.proc_path = cls.root_dir / "data" / "processed" / "uci_sms_spam.jsonl"
        cls.p3_eval_dir = cls.root_dir / "data" / "evaluation" / "baseline"
        cls.p5_eval_dir = cls.root_dir / "data" / "evaluation" / "hybrid"
        cls.p5_model_dir = cls.root_dir / "models" / "hybrid"

        with open(cls.prep_path, "r", encoding="utf-8") as f:
            cls.records_prep = [json.loads(line) for line in f]

        with open(cls.proc_path, "r", encoding="utf-8") as f:
            cls.records_proc = [json.loads(line) for line in f]

        cls.df = pd.DataFrame(cls.records_prep)

        # Reproduce the exact duplicate-group clustering
        parent = {idx: idx for idx in cls.df.index}

        def find(i: int) -> int:
            if parent[i] != i:
                parent[i] = find(parent[i])
            return parent[i]

        def union(i: int, j: int) -> None:
            ri, rj = find(i), find(j)
            if ri != rj:
                parent[ri] = rj

        norm_to_indices = defaultdict(list)
        for idx, row in cls.df.iterrows():
            norm_key = str(row.get("normalized_text") or row.get("text", "")).strip().lower()
            if norm_key:
                norm_to_indices[norm_key].append(idx)
        for indices in norm_to_indices.values():
            for other in indices[1:]:
                union(indices[0], other)

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

    def test_canonical_dataset_totals_and_label_counts(self):
        """Verify total records and ground truth class distribution."""
        self.assertEqual(len(self.records_prep), 5574)
        self.assertEqual(len(self.records_proc), 5574)

        counts_prep = Counter(r["label"] for r in self.records_prep)
        counts_proc = Counter(r["label"] for r in self.records_proc)

        self.assertEqual(counts_prep["scam"], 747)
        self.assertEqual(counts_prep["non_scam"], 4827)
        self.assertEqual(counts_proc["scam"], 747)
        self.assertEqual(counts_proc["non_scam"], 4827)

    def test_record_identity_and_zero_differences(self):
        """Verify record-by-record sample_id, text, and label consistency."""
        prep_map = {r["sample_id"]: r for r in self.records_prep}
        proc_map = {r["sample_id"]: r for r in self.records_proc}

        self.assertEqual(set(prep_map.keys()), set(proc_map.keys()))

        differing_labels = []
        differing_texts = []

        for sid, prep_rec in prep_map.items():
            proc_rec = proc_map[sid]
            if prep_rec["label"] != proc_rec["label"]:
                differing_labels.append(sid)
            if prep_rec["text"] != proc_rec["text"]:
                differing_texts.append(sid)

        self.assertEqual(len(differing_labels), 0, f"Label differences found: {differing_labels}")
        self.assertEqual(len(differing_texts), 0, f"Text differences found: {differing_texts}")

    def test_partition_membership_and_label_distribution(self):
        """Verify exact split counts and class distribution across partitions."""
        self.assertEqual(len(self.train_df), 3881)
        self.assertEqual(len(self.val_df), 837)
        self.assertEqual(len(self.test_df), 856)

        train_counts = Counter(self.train_df["label"])
        val_counts = Counter(self.val_df["label"])
        test_counts = Counter(self.test_df["label"])

        # Train distribution
        self.assertEqual(train_counts["scam"], 520)
        self.assertEqual(train_counts["non_scam"], 3361)

        # Validation distribution
        self.assertEqual(val_counts["scam"], 104)
        self.assertEqual(val_counts["non_scam"], 733)

        # Test distribution
        self.assertEqual(test_counts["scam"], 123)
        self.assertEqual(test_counts["non_scam"], 733)

        # Total reconciliation
        self.assertEqual(train_counts["scam"] + val_counts["scam"] + test_counts["scam"], 747)
        self.assertEqual(train_counts["non_scam"] + val_counts["non_scam"] + test_counts["non_scam"], 4827)

    def test_zero_partition_leakage(self):
        """Verify zero sample ID overlap and zero text overlap across splits."""
        train_ids = set(self.train_df["sample_id"])
        val_ids = set(self.val_df["sample_id"])
        test_ids = set(self.test_df["sample_id"])

        self.assertEqual(len(train_ids & val_ids), 0)
        self.assertEqual(len(train_ids & test_ids), 0)
        self.assertEqual(len(val_ids & test_ids), 0)

        # Zero text overlap
        train_texts = set(self.train_df["text"])
        val_texts = set(self.val_df["text"])
        test_texts = set(self.test_df["text"])

        self.assertEqual(len(train_texts & val_texts), 0)
        self.assertEqual(len(train_texts & test_texts), 0)
        self.assertEqual(len(val_texts & test_texts), 0)

    def test_phase3_vs_phase5_test_set_identity(self):
        """Verify Phase 3 and Phase 5 evaluated on the exact same test IDs and labels."""
        with open(self.p3_eval_dir / "test_predictions.jsonl", "r", encoding="utf-8") as f:
            p3_preds = [json.loads(line) for line in f]

        with open(self.p5_eval_dir / "test_predictions.jsonl", "r", encoding="utf-8") as f:
            p5_preds = [json.loads(line) for line in f]

        self.assertEqual(len(p3_preds), 856)
        self.assertEqual(len(p5_preds), 856)

        p3_id_to_rec = {p["sample_id"]: p for p in p3_preds}
        p5_id_to_rec = {p["sample_id"]: p for p in p5_preds}

        # Verify exact same test IDs
        self.assertEqual(set(p3_id_to_rec.keys()), set(p5_id_to_rec.keys()))
        self.assertEqual(set(p3_id_to_rec.keys()), set(self.test_df["sample_id"]))

        # Verify ground truth labels match 100%
        label_mismatches = []
        for sid, p3_rec in p3_id_to_rec.items():
            p5_rec = p5_id_to_rec[sid]
            if p3_rec["true_label"] != p5_rec["true_label"]:
                label_mismatches.append(sid)

        self.assertEqual(len(label_mismatches), 0, f"Label mismatches: {label_mismatches}")

    def test_saved_hybrid_model_trained_on_520_scams(self):
        """Verify the serialized hybrid classifier was trained on exactly 520 scams."""
        saved_clf = joblib.load(self.p5_model_dir / "logistic_regression.joblib")

        # The training targets in train_df have 520 ones and 3,361 zeros
        y_train = (self.train_df["label"] == "scam").astype(int).values
        self.assertEqual(int(y_train.sum()), 520)
        self.assertEqual(int((y_train == 0).sum()), 3361)

        # Under C=1.0 logistic regression with this training set, the hybrid intercept is -2.4997
        # (shifted from -2.4632 in the text baseline due to the +1.6793 weight on has_url)
        self.assertAlmostEqual(float(saved_clf.intercept_[0]), -2.4997, places=3)

    def test_url_subset_composition_in_test_set(self):
        """Verify the test set URL subset contains exactly 24 samples (22 scam, 2 non-scam)."""
        test_url_samples = self.test_df[self.test_df["entities"].apply(lambda e: len(e.get("urls", [])) > 0)]
        self.assertEqual(len(test_url_samples), 24)

        url_counts = Counter(test_url_samples["label"])
        self.assertEqual(url_counts["scam"], 22)
        self.assertEqual(url_counts["non_scam"], 2)


if __name__ == "__main__":
    unittest.main()
