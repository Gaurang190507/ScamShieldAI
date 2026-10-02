"""Dataset descriptive statistics and distribution profiling utility."""

from collections import Counter
from typing import Dict, Any, Union, List
import pandas as pd


def generate_dataset_statistics(
    data: Union[pd.DataFrame, List[Dict[str, Any]]]
) -> Dict[str, Any]:
    """Computes comprehensive dataset distributions and integrity metrics.

    Args:
        data: DataFrame or list of sample records.

    Returns:
        Structured dictionary containing counts, distributions, and integrity indicators.
    """
    if isinstance(data, pd.DataFrame):
        records = data.to_dict(orient="records")
    else:
        records = list(data)

    total_samples = len(records)
    if total_samples == 0:
        return {
            "total_samples": 0,
            "label_distribution": {},
            "scam_category_distribution": {},
            "tactic_frequencies": {},
            "language_distribution": {},
            "source_type_distribution": {},
            "unique_pattern_groups": 0,
            "known_unknown_distribution": {},
            "missing_values": {},
            "duplicate_text_count": 0,
        }

    label_counts = Counter()
    category_counts = Counter()
    tactic_counts = Counter()
    language_counts = Counter()
    source_counts = Counter()
    pattern_groups = set()
    status_counts = Counter()
    text_counter = Counter()
    missing_counts = Counter()

    for r in records:
        label_counts[r.get("label", "missing")] += 1
        category_counts[r.get("scam_category", "missing")] += 1
        language_counts[r.get("language", "missing")] += 1
        source_counts[r.get("source_type", "missing")] += 1
        status_counts[r.get("known_unknown_status", "missing")] += 1

        pg = r.get("pattern_group_id")
        if pg:
            pattern_groups.add(pg)

        txt = r.get("text", "")
        if txt:
            text_counter[txt] += 1

        tactics = r.get("tactics", [])
        if isinstance(tactics, list):
            for t in tactics:
                tactic_counts[t] += 1

        for k, v in r.items():
            if v is None or (isinstance(v, str) and not v.strip()):
                missing_counts[k] += 1

    duplicate_exact_count = sum(c - 1 for c in text_counter.values() if c > 1)

    return {
        "total_samples": total_samples,
        "label_distribution": dict(label_counts),
        "scam_category_distribution": dict(category_counts),
        "tactic_frequencies": dict(tactic_counts.most_common()),
        "language_distribution": dict(language_counts),
        "source_type_distribution": dict(source_counts),
        "unique_pattern_groups": len(pattern_groups),
        "known_unknown_distribution": dict(status_counts),
        "missing_values": dict(missing_counts),
        "duplicate_text_count": duplicate_exact_count,
    }


def format_statistics_report(stats: Dict[str, Any]) -> str:
    """Renders formatted text report summarizing dataset distributions."""
    lines = [
        "==================================================",
        "           SCAMSHIELD AI DATASET REPORT           ",
        "==================================================",
        f"Total Samples: {stats['total_samples']}",
        f"Unique Pattern Groups: {stats['unique_pattern_groups']}",
        f"Exact Duplicate Texts: {stats['duplicate_text_count']}",
        "",
        "--- Label Distribution ---",
    ]
    for lbl, count in stats.get("label_distribution", {}).items():
        pct = (count / stats["total_samples"] * 100) if stats["total_samples"] else 0
        lines.append(f"  {lbl}: {count} ({pct:.1f}%)")

    lines.append("\n--- Top Tactic Frequencies ---")
    tactics = stats.get("tactic_frequencies", {})
    if not tactics:
        lines.append("  (None assigned)")
    else:
        for t, count in list(tactics.items())[:10]:
            lines.append(f"  {t}: {count}")

    lines.append("\n--- Known / Unknown Status ---")
    for st, count in stats.get("known_unknown_distribution", {}).items():
        lines.append(f"  {st}: {count}")

    lines.append("==================================================")
    return "\n".join(lines)
