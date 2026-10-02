"""Leakage-safe group-based dataset splitting utilities.

WHY RANDOM ROW-LEVEL SPLITTING PRODUCES MISLEADING RESULTS:
-----------------------------------------------------------
Threat actors frequently deploy automated spam/phishing kits that broadcast
thousands of superficial variations of the exact same underlying template
(e.g., swapping a random 4-digit reference code or changing a victim's name).

If a naive, random row-level train/test split is performed, variants of the same
template will inevitably populate both the training set and the test set. The ML
model merely memorizes verbatim lexical artifacts from the template rather than
learning generalizable behavioral indicators of coercion or fraud. This yields
artificially inflated benchmark scores (e.g., >98% accuracy) that catastrophically
collapse when exposed to fresh scam campaigns in real-world deployment.

To establish genuine generalization to unseen campaigns, dataset partitioning MUST
strictly group all variants belonging to the same 'pattern_group_id' into the same
partition (either train, validation, or test, but never across multiple partitions).
"""

from typing import Tuple, Set, Optional
import numpy as np
import pandas as pd


def group_leakage_split(
    df: pd.DataFrame,
    group_col: str = "pattern_group_id",
    test_size: float = 0.2,
    val_size: float = 0.1,
    random_state: int = 42,
) -> Tuple[pd.DataFrame, pd.DataFrame, pd.DataFrame]:
    """Partitions a dataset into train, validation, and test splits by grouping pattern IDs.

    Ensures that zero pattern groups are shared across train, val, and test subsets.

    Args:
        df: Input DataFrame containing annotated samples.
        group_col: Column name indicating campaign/template cluster. Defaults to 'pattern_group_id'.
        test_size: Proportion of unique groups allocated to the test split.
        val_size: Proportion of unique groups allocated to the validation split.
        random_state: Random seed for deterministic group shuffling.

    Returns:
        Tuple of (train_df, val_df, test_df).

    Raises:
        ValueError: If group_col is missing or split ratios exceed 1.0.
    """
    if group_col not in df.columns:
        raise ValueError(f"Required group column '{group_col}' not found in DataFrame.")

    if test_size + val_size >= 1.0 or test_size <= 0.0 or val_size < 0.0:
        raise ValueError("Invalid split proportions: test_size + val_size must be strictly between 0 and 1.")

    unique_groups = df[group_col].dropna().unique()
    if len(unique_groups) < 3:
        raise ValueError(
            f"Dataset requires at least 3 distinct '{group_col}' values to perform a 3-way split, "
            f"found {len(unique_groups)}."
        )

    rng = np.random.default_rng(random_state)
    shuffled_groups = rng.permutation(unique_groups)

    n_groups = len(shuffled_groups)
    n_test = max(1, int(round(n_groups * test_size)))
    n_val = max(1, int(round(n_groups * val_size))) if val_size > 0 else 0

    test_groups: Set[str] = set(shuffled_groups[:n_test])
    val_groups: Set[str] = set(shuffled_groups[n_test : n_test + n_val])
    train_groups: Set[str] = set(shuffled_groups[n_test + n_val :])

    train_df = df[df[group_col].isin(train_groups)].copy()
    val_df = df[df[group_col].isin(val_groups)].copy()
    test_df = df[df[group_col].isin(test_groups)].copy()

    return train_df, val_df, test_df


def verify_no_group_leakage(
    train_df: pd.DataFrame,
    val_df: pd.DataFrame,
    test_df: pd.DataFrame,
    group_col: str = "pattern_group_id",
) -> Tuple[bool, str]:
    """Verifies that no pattern group appears in more than one partition.

    Returns:
        Tuple of (is_leakage_free: bool, diagnostic_message: str).
    """
    train_groups = set(train_df[group_col].dropna().unique())
    val_groups = set(val_df[group_col].dropna().unique())
    test_groups = set(test_df[group_col].dropna().unique())

    tv_overlap = train_groups.intersection(val_groups)
    tt_overlap = train_groups.intersection(test_groups)
    vt_overlap = val_groups.intersection(test_groups)

    if tv_overlap or tt_overlap or vt_overlap:
        msg = (
            f"LEAKAGE DETECTED! Overlaps: Train/Val={len(tv_overlap)}, "
            f"Train/Test={len(tt_overlap)}, Val/Test={len(vt_overlap)}"
        )
        return False, msg

    return True, "Splits are verified 100% leakage-free across pattern groups."
