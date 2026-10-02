"""Unit tests for Phase 9B visual data leakage prevention and forensic audit."""

import unittest
from PIL import Image

from src.vision.leakage import (
    audit_visual_leakage,
    compute_dhash,
    compute_image_sha256,
    hamming_distance,
    partition_by_group,
)
from src.vision.schemas import VisualSampleRecord


class TestVisualLeakage(unittest.TestCase):
    """Verifies image hashing, dHash distance, group partitioning, and audit detection."""

    def setUp(self):
        self.img1 = Image.new("RGB", (100, 100), color=(255, 0, 0))
        self.img2 = Image.new("RGB", (100, 100), color=(0, 255, 0))
        # Add subtle variation
        for x in range(50):
            self.img2.putpixel((x, 50), (255, 255, 255))

    def test_sha256_exact_hashing(self):
        """Identical image rasters must yield identical SHA256; differing yield distinct."""
        h1 = compute_image_sha256(self.img1)
        h1_dup = compute_image_sha256(self.img1)
        h2 = compute_image_sha256(self.img2)

        self.assertEqual(h1, h1_dup)
        self.assertNotEqual(h1, h2)
        self.assertEqual(len(h1), 64)

    def test_dhash_and_hamming_distance(self):
        """dHash produces 16-char hex and Hamming distance reflects similarity."""
        dh1 = compute_dhash(self.img1)
        dh2 = compute_dhash(self.img2)

        self.assertEqual(len(dh1), 16)
        self.assertEqual(len(dh2), 16)

        dist_self = hamming_distance(dh1, dh1)
        self.assertEqual(dist_self, 0)

        # Bit distance must be bounded in [0, 64]
        dist_diff = hamming_distance(dh1, dh2)
        self.assertGreaterEqual(dist_diff, 0)
        self.assertLessEqual(dist_diff, 64)

    def test_partition_by_group_zero_cross_overlap(self):
        """Records with the same pattern_group_id must strictly end up in the same split."""
        records = [
            VisualSampleRecord(
                image_id=f"rec_{i}",
                image_path=f"path_{i}.png",
                label="scam" if i % 2 == 0 else "non_scam",
                source_type="synthetic",
                scenario="test",
                pattern_group_id=f"group_{i // 2}",  # 2 items per group
                image_hash=f"hash_{i}",
                perceptual_hash=f"{i:016x}",
            )
            for i in range(12)
        ]

        train_recs, val_recs, test_recs = partition_by_group(records)

        train_groups = {r.pattern_group_id for r in train_recs}
        val_groups = {r.pattern_group_id for r in val_recs}
        test_groups = {r.pattern_group_id for r in test_recs}

        # Zero group overlap across splits
        self.assertEqual(len(train_groups & val_groups), 0)
        self.assertEqual(len(train_groups & test_groups), 0)
        self.assertEqual(len(val_groups & test_groups), 0)

    def test_leakage_audit_detects_injected_violations(self):
        """Leakage audit must catch exact hash, perceptual near-duplicate, and group overlaps."""
        r_train = VisualSampleRecord(
            image_id="tr_1",
            image_path="p1.png",
            label="scam",
            source_type="synthetic",
            scenario="test",
            pattern_group_id="grp_A",
            image_hash="exact_hash_1",
            perceptual_hash="0000000000000000",
            split="train",
        )
        # Injected duplicate into val
        r_val_leaked = VisualSampleRecord(
            image_id="val_1",
            image_path="p2.png",
            label="scam",
            source_type="synthetic",
            scenario="test",
            pattern_group_id="grp_A",  # Group overlap!
            image_hash="exact_hash_1",  # Exact duplicate!
            perceptual_hash="0000000000000001",  # Hamming dist 1 (near duplicate)!
            split="val",
        )

        report = audit_visual_leakage([r_train], [r_val_leaked], [])
        self.assertFalse(report.is_leakage_free)
        self.assertGreater(report.exact_duplicate_overlap, 0)
        self.assertGreater(report.perceptual_duplicate_overlap, 0)
        self.assertGreater(report.pattern_group_overlap, 0)


if __name__ == "__main__":
    unittest.main()
