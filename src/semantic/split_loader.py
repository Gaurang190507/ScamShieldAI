"""Reproducible split loader for Phase 7 semantic reference and evaluation partitions.

Strictly reproduces the authoritative Phase 3 group-leakage clustering:
- 5,574 total UCI SMS records
- TRAIN: 3,881 samples (Reference Corpus)
- VALIDATION: 837 samples (Evaluation Query Set)
- TEST: 856 samples (Held-out Test Query Set)
Guarantees zero duplicate or normalized text leakage across partitions.
"""

from collections import defaultdict
import json
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple, Union
import pandas as pd

from src.data.leakage_split import group_leakage_split, verify_no_group_leakage


def load_canonical_splits(
    dataset_path: Optional[Union[str, Path]] = None,
    random_state: int = 42,
) -> Tuple[pd.DataFrame, pd.DataFrame, pd.DataFrame]:
    """Loads and partitions the canonical preprocessed dataset using Phase 3 clustering.

    Args:
        dataset_path: Path to preprocessed uci_sms_spam.jsonl dataset.
        random_state: Fixed random seed matching Phase 3 baseline (42).

    Returns:
        Tuple of (train_df, val_df, test_df).
    """
    root_dir = Path(__file__).resolve().parents[2]
    if dataset_path is None:
        dataset_path = (
            root_dir / "data" / "processed" / "preprocessed" / "uci_sms_spam.jsonl"
        )
    data_file = Path(dataset_path).resolve()

    if not data_file.is_file():
        raise FileNotFoundError(f"Canonical dataset missing at: {data_file}")

    records: List[Dict[str, Any]] = []
    with open(data_file, "r", encoding="utf-8") as f:
        for line in f:
            line_str = line.strip()
            if line_str:
                records.append(json.loads(line_str))

    df = pd.DataFrame(records)

    # Reproduce disjoint-set clustering on normalized text and pattern groups
    parent = {idx: idx for idx in df.index}

    def find(i: int) -> int:
        if parent[i] != i:
            parent[i] = find(parent[i])
        return parent[i]

    def union(i: int, j: int) -> None:
        ri, rj = find(i), find(j)
        if ri != rj:
            parent[ri] = rj

    # A. Cluster samples sharing identical normalized text
    norm_to_indices: Dict[str, List[int]] = defaultdict(list)
    for idx, row in df.iterrows():
        norm_key = str(row.get("normalized_text") or row.get("text", "")).strip().lower()
        if norm_key:
            norm_to_indices[norm_key].append(idx)

    for indices in norm_to_indices.values():
        for other in indices[1:]:
            union(indices[0], other)

    # B. Cluster samples sharing genuine multi-record pattern groups
    grp_to_indices: Dict[str, List[int]] = defaultdict(list)
    for idx, row in df.iterrows():
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

    df["_split_cluster_id"] = [f"cluster_{find(i)}" for i in df.index]

    train_df, val_df, test_df = group_leakage_split(
        df,
        group_col="_split_cluster_id",
        test_size=0.15,
        val_size=0.15,
        random_state=random_state,
    )

    # Verify zero leakage
    is_clean, leak_msg = verify_no_group_leakage(
        train_df, val_df, test_df, group_col="_split_cluster_id"
    )
    if not is_clean:
        raise RuntimeError(f"Split leakage assertion failed: {leak_msg}")

    # Check expected partition sizes
    if len(train_df) != 3881 or len(val_df) != 837 or len(test_df) != 856:
        raise ValueError(
            f"Unexpected partition counts: Train={len(train_df)} (exp 3881), "
            f"Val={len(val_df)} (exp 837), Test={len(test_df)} (exp 856)"
        )

    return train_df, val_df, test_df
