"""Duplicate detection identifying exact and normalized duplicate samples without automatic deletion."""

from dataclasses import dataclass, field
import re
import string
from typing import Dict, List, Any, Union
import pandas as pd


@dataclass
class DuplicateReport:
    """Detailed summary of exact and normalized duplicates identified in the dataset."""
    exact_duplicates: Dict[str, List[str]] = field(default_factory=dict)
    normalized_duplicates: Dict[str, List[str]] = field(default_factory=dict)
    total_exact_duplicates: int = 0
    total_normalized_duplicates: int = 0

    def summary(self) -> str:
        """Formatted overview of duplicate clusters."""
        lines = [
            f"Duplicate Report: {len(self.exact_duplicates)} exact cluster(s) "
            f"({self.total_exact_duplicates} excess samples), "
            f"{len(self.normalized_duplicates)} normalized cluster(s) "
            f"({self.total_normalized_duplicates} excess samples)."
        ]
        return "\n".join(lines)


def normalize_text_for_dedup(text: str) -> str:
    """Standardizes text by lowercasing, stripping punctuation, and compressing whitespace.

    Args:
        text: Input message string.

    Returns:
        Normalized text signature string.
    """
    if not isinstance(text, str):
        return ""
    # Lowercase
    t = text.lower()
    # Strip punctuation
    t = t.translate(str.maketrans("", "", string.punctuation))
    # Normalize whitespace
    t = re.sub(r"\s+", " ", t).strip()
    return t


def detect_duplicates(
    data: Union[pd.DataFrame, List[Dict[str, Any]]]
) -> DuplicateReport:
    """Scans dataset for identical and near-identical messages.

    NOTE: Does NOT drop or modify duplicates. Reports them for manual review.

    Args:
        data: DataFrame or list of sample records.

    Returns:
        DuplicateReport grouping matching sample_ids under respective text keys.
    """
    if isinstance(data, pd.DataFrame):
        records = data.to_dict(orient="records")
    else:
        records = list(data)

    exact_map: Dict[str, List[str]] = {}
    normalized_map: Dict[str, List[str]] = {}

    for idx, r in enumerate(records):
        s_id = str(r.get("sample_id", f"row_{idx}"))
        raw_text = r.get("text", "")

        if not raw_text:
            continue

        # Exact grouping
        exact_map.setdefault(raw_text, []).append(s_id)

        # Normalized grouping
        norm_key = normalize_text_for_dedup(raw_text)
        if norm_key:
            normalized_map.setdefault(norm_key, []).append(s_id)

    # Filter to only groups with >1 sample (actual duplicates)
    exact_dups = {k: ids for k, ids in exact_map.items() if len(ids) > 1}
    norm_dups = {k: ids for k, ids in normalized_map.items() if len(ids) > 1}

    excess_exact = sum(len(ids) - 1 for ids in exact_dups.values())
    excess_norm = sum(len(ids) - 1 for ids in norm_dups.values())

    return DuplicateReport(
        exact_duplicates=exact_dups,
        normalized_duplicates=norm_dups,
        total_exact_duplicates=excess_exact,
        total_normalized_duplicates=excess_norm,
    )
