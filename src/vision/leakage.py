"""Data leakage prevention and audit utilities for ScamShield AI Phase 9B.

Ensures strict zero-leakage invariants across visual dataset splits:
1. Exact Image Hash (SHA-256): Detects identical pixel byte rasters.
2. Perceptual Hash (64-bit dHash): Detects near-identical or rescaled visual artifacts.
3. Group-Level Partitioning: Clusters visual templates by `pattern_group_id` so that
   no layout or design pattern is shared across train, val, and test splits.
4. Comprehensive Leakage Audit: Forensically validates split isolation.
"""

import hashlib
from io import BytesIO
from pathlib import Path
import random
from typing import Dict, List, Optional, Sequence, Set, Tuple, Union
import numpy as np
from PIL import Image

from .schemas import VisualLeakageReport, VisualSampleRecord


def compute_image_sha256(image_input: Union[Image.Image, Path, str, bytes]) -> str:
    """Computes exact SHA-256 hash of image data."""
    if isinstance(image_input, (str, Path)):
        path = Path(image_input)
        if not path.is_file():
            raise FileNotFoundError(f"Image not found at path: {path}")
        return hashlib.sha256(path.read_bytes()).hexdigest()
    elif isinstance(image_input, bytes):
        return hashlib.sha256(image_input).hexdigest()
    elif isinstance(image_input, Image.Image):
        # Convert image to canonical PNG byte stream for consistent hashing
        buffer = BytesIO()
        image_input.convert("RGB").save(buffer, format="PNG")
        return hashlib.sha256(buffer.getvalue()).hexdigest()
    else:
        raise TypeError(f"Unsupported image input type: {type(image_input)}")


def compute_dhash(
    image_input: Union[Image.Image, Path, str], hash_size: int = 8
) -> str:
    """Computes 64-bit difference hash (dHash) for perceptual image comparison.

    Procedure:
    1. Convert image to grayscale.
    2. Resize to (hash_size + 1, hash_size), e.g., 9x8 pixels.
    3. Compare adjacent horizontal pixels (pixel[c] > pixel[c+1]).
    4. Pack resulting 64 booleans into a 16-character hexadecimal string.

    Args:
        image_input: PIL Image or filesystem path.
        hash_size: Grid height and width basis. Defaults to 8 (64-bit hash).

    Returns:
        16-character hex string representing the 64-bit perceptual hash.
    """
    if isinstance(image_input, (str, Path)):
        img = Image.open(image_input).convert("L")
    elif isinstance(image_input, Image.Image):
        img = image_input.convert("L")
    else:
        raise TypeError(f"Unsupported image input type: {type(image_input)}")

    # Resize to (width = hash_size + 1, height = hash_size)
    resized = img.resize((hash_size + 1, hash_size), Image.Resampling.BILINEAR)
    pixels = np.array(resized, dtype=np.int32)

    # Compare adjacent pixels in each row
    diff = pixels[:, :-1] > pixels[:, 1:]

    # Flatten and pack bits into integer
    bits = diff.flatten()
    hash_int = 0
    for bit in bits:
        hash_int = (hash_int << 1) | int(bit)

    # Format as 16-digit lowercase hex string
    hex_len = (hash_size * hash_size) // 4
    return f"{hash_int:0{hex_len}x}"


def hamming_distance(hash1: str, hash2: str) -> int:
    """Computes bitwise Hamming distance between two hexadecimal hash strings."""
    if not hash1 or not hash2:
        return 64
    val1 = int(hash1, 16)
    val2 = int(hash2, 16)
    return bin(val1 ^ val2).count("1")


def partition_by_group(
    records: Sequence[VisualSampleRecord],
    train_ratio: float = 0.60,
    val_ratio: float = 0.20,
    test_ratio: float = 0.20,
    seed: int = 42,
) -> Tuple[List[VisualSampleRecord], List[VisualSampleRecord], List[VisualSampleRecord]]:
    """Partitions visual records strictly by `pattern_group_id` into train/val/test splits.

    Guarantees:
    - Every record in the same `pattern_group_id` is assigned to exactly ONE split.
    - Zero `pattern_group_id` overlap exists across train, val, and test splits.
    - Class balance (scam vs. non-scam) is preserved as closely as possible.

    Args:
        records: Collection of VisualSampleRecord instances.
        train_ratio: Desired target fraction for training.
        val_ratio: Desired target fraction for validation.
        test_ratio: Desired target fraction for test.
        seed: Random seed for deterministic reproducibility.

    Returns:
        Tuple of (train_records, val_records, test_records).
    """
    if not records:
        return [], [], []

    # Group records by pattern_group_id
    groups: Dict[str, List[VisualSampleRecord]] = {}
    group_labels: Dict[str, str] = {}
    for r in records:
        groups.setdefault(r.pattern_group_id, []).append(r)
        # Dominant label in group
        group_labels[r.pattern_group_id] = r.label

    # Sort groups deterministically, then shuffle with seeded RNG
    rng = random.Random(seed)
    scam_groups = sorted([g for g, lbl in group_labels.items() if lbl == "scam"])
    non_scam_groups = sorted([g for g, lbl in group_labels.items() if lbl != "scam"])

    rng.shuffle(scam_groups)
    rng.shuffle(non_scam_groups)

    train_groups: Set[str] = set()
    val_groups: Set[str] = set()
    test_groups: Set[str] = set()

    def allocate_groups(group_list: List[str]) -> None:
        """Allocates groups proportionally to maintain class balance."""
        total_items = sum(len(groups[g]) for g in group_list)
        target_train = total_items * train_ratio
        target_val = total_items * val_ratio

        curr_train = 0
        curr_val = 0

        for g in group_list:
            cnt = len(groups[g])
            if curr_train + cnt <= target_train or (curr_train == 0 and len(train_groups) == 0):
                train_groups.add(g)
                curr_train += cnt
            elif curr_val + cnt <= target_val or (curr_val == 0 and len(val_groups) == 0):
                val_groups.add(g)
                curr_val += cnt
            else:
                test_groups.add(g)

    allocate_groups(scam_groups)
    allocate_groups(non_scam_groups)

    train_records: List[VisualSampleRecord] = []
    val_records: List[VisualSampleRecord] = []
    test_records: List[VisualSampleRecord] = []

    for r in records:
        if r.pattern_group_id in train_groups:
            r.split = "train"
            train_records.append(r)
        elif r.pattern_group_id in val_groups:
            r.split = "val"
            val_records.append(r)
        elif r.pattern_group_id in test_groups:
            r.split = "test"
            test_records.append(r)
        else:
            # Fallback to train
            r.split = "train"
            train_records.append(r)

    return train_records, val_records, test_records


def audit_visual_leakage(
    train_records: Sequence[VisualSampleRecord],
    val_records: Sequence[VisualSampleRecord],
    test_records: Sequence[VisualSampleRecord],
    dhash_threshold: int = 2,
) -> VisualLeakageReport:
    """Forensically audits splits to verify zero cross-split leakage.

    Checks:
    1. Exact image hash overlaps across (train, val), (train, test), and (val, test).
    2. Perceptual hash near-duplicates (Hamming distance <= dhash_threshold).
    3. Pattern group ID overlaps across splits.

    Args:
        train_records: Visual samples in training split.
        val_records: Visual samples in validation split.
        test_records: Visual samples in test split.
        dhash_threshold: Maximum Hamming distance considered a perceptual near-duplicate.

    Returns:
        VisualLeakageReport detailing findings and pass/fail certification.
    """
    notes: List[str] = []
    splits = {
        "train": train_records,
        "val": val_records,
        "test": test_records,
    }

    # 1. Pattern Group ID Overlap
    group_sets = {name: {r.pattern_group_id for r in recs} for name, recs in splits.items()}
    train_val_group_overlap = len(group_sets["train"] & group_sets["val"])
    train_test_group_overlap = len(group_sets["train"] & group_sets["test"])
    val_test_group_overlap = len(group_sets["val"] & group_sets["test"])
    total_group_overlap = (
        train_val_group_overlap + train_test_group_overlap + val_test_group_overlap
    )

    if total_group_overlap > 0:
        notes.append(
            f"VIOLATION: Found {total_group_overlap} overlapping pattern_group_id(s) across splits."
        )

    # 2. Exact Hash Overlap
    hash_sets = {
        name: {r.image_hash for r in recs if r.image_hash}
        for name, recs in splits.items()
    }
    train_val_hash_overlap = len(hash_sets["train"] & hash_sets["val"])
    train_test_hash_overlap = len(hash_sets["train"] & hash_sets["test"])
    val_test_hash_overlap = len(hash_sets["val"] & hash_sets["test"])
    total_hash_overlap = (
        train_val_hash_overlap + train_test_hash_overlap + val_test_hash_overlap
    )

    if total_hash_overlap > 0:
        notes.append(
            f"VIOLATION: Found {total_hash_overlap} exact hash duplicate(s) across splits."
        )

    # 3. Perceptual Hash (dHash) Near-Duplicate Overlap
    perceptual_duplicates = 0
    split_names = ["train", "val", "test"]
    for i in range(len(split_names)):
        for j in range(i + 1, len(split_names)):
            name_a, name_b = split_names[i], split_names[j]
            for r_a in splits[name_a]:
                if not r_a.perceptual_hash:
                    continue
                for r_b in splits[name_b]:
                    if not r_b.perceptual_hash:
                        continue
                    dist = hamming_distance(r_a.perceptual_hash, r_b.perceptual_hash)
                    if dist <= dhash_threshold:
                        perceptual_duplicates += 1
                        notes.append(
                            f"Near-duplicate between {name_a}:{r_a.image_id} and {name_b}:{r_b.image_id} "
                            f"(Hamming distance: {dist} <= {dhash_threshold})"
                        )

    is_leakage_free = (
        total_group_overlap == 0 and total_hash_overlap == 0 and perceptual_duplicates == 0
    )

    if is_leakage_free:
        notes.append("AUDIT PASSED: Zero exact, perceptual, or group leakage detected across splits.")

    return VisualLeakageReport(
        train_count=len(train_records),
        val_count=len(val_records),
        test_count=len(test_records),
        exact_duplicate_overlap=total_hash_overlap,
        perceptual_duplicate_overlap=perceptual_duplicates,
        pattern_group_overlap=total_group_overlap,
        is_leakage_free=is_leakage_free,
        audit_notes=notes,
    )
