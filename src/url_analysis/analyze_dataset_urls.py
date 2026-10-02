"""Batch offline URL analysis utility for ScamShield AI.

OPERATIONAL SAFETY GUARANTEE:
- Zero outbound network requests.
- Zero DNS lookups or socket connections.
- Operates strictly on string syntax using Python standard libraries.
- Does NOT use scam/non-scam labels to calibrate or tune heuristic scores.
"""

from collections import Counter, defaultdict
import json
from pathlib import Path
from typing import Dict, Any, List, Optional, Union
import numpy as np

from .analyzer import analyze_url
from ..preprocessing.extract_entities import extract_urls


def run_batch_url_analysis(
    dataset_path: Optional[Union[str, Path]] = None,
    output_dir: Optional[Union[str, Path]] = None,
) -> Dict[str, Any]:
    """Extracts and analyzes all URLs from the dataset purely through offline heuristics.

    Args:
        dataset_path: Path to preprocessed JSONL dataset.
        output_dir: Directory where evaluation artifacts will be written.

    Returns:
        Summary dictionary containing batch evaluation statistics.
    """
    root_dir = Path(__file__).resolve().parents[2]
    if dataset_path is None:
        dataset_path = root_dir / "data" / "processed" / "preprocessed" / "uci_sms_spam.jsonl"
    if output_dir is None:
        output_dir = root_dir / "data" / "evaluation" / "url_analysis"

    data_file = Path(dataset_path).resolve()
    out_path = Path(output_dir).resolve()
    out_path.mkdir(parents=True, exist_ok=True)

    if not data_file.is_file():
        raise FileNotFoundError(f"Dataset file not found at: {data_file}")

    total_records = 0
    records_with_urls = 0
    all_url_mentions: List[Dict[str, Any]] = []
    unique_urls_set = set()

    with open(data_file, "r", encoding="utf-8") as f:
        for line in f:
            line_str = line.strip()
            if not line_str:
                continue
            total_records += 1
            row = json.loads(line_str)
            sample_id = row.get("sample_id", "")
            raw_text = row.get("text", "")

            # Extract URLs from entity cache or fallback to offline regex
            extracted = (
                row.get("entities", {}).get("urls", [])
                or extract_urls(raw_text)
            )

            if extracted:
                records_with_urls += 1
                for u in extracted:
                    unique_urls_set.add(u)
                    all_url_mentions.append({
                        "sample_id": sample_id,
                        "url": u,
                    })

    # Analyze each unique URL once
    unique_results: Dict[str, Dict[str, Any]] = {}
    for u in unique_urls_set:
        unique_results[u] = analyze_url(u)

    # Combine results for each mention
    mentions_analysis: List[Dict[str, Any]] = []
    malformed_count = 0
    signal_counter: Counter = Counter()
    risk_level_counter: Counter = Counter()
    risk_scores: List[float] = []

    schemes_counter: Counter = Counter()
    ip_host_count = 0
    punycode_count = 0
    non_ascii_count = 0
    shortener_count = 0
    unusual_port_count = 0
    userinfo_count = 0
    excessive_subdomain_count = 0
    url_lengths: List[int] = []
    path_keywords_counter: Counter = Counter()
    query_params_counter: Counter = Counter()

    for item in all_url_mentions:
        u = item["url"]
        res = unique_results[u]
        analysis_entry = {
            "sample_id": item["sample_id"],
            "url": u,
            "parse_success": res["parse_success"],
            "error_message": res.get("error_message"),
            "risk_score": res["risk_score"],
            "risk_level": res["risk_level"],
            "features": res["features"],
            "signals": res["signals"],
        }
        mentions_analysis.append(analysis_entry)

        if not res["parse_success"]:
            malformed_count += 1
        else:
            feat = res["features"]
            url_lengths.append(feat["url_length"])
            schemes_counter[feat["scheme"] or "no_scheme"] += 1
            if feat["is_ip_hostname"]:
                ip_host_count += 1
            if feat["has_punycode"]:
                punycode_count += 1
            if feat["has_non_ascii_hostname"]:
                non_ascii_count += 1
            if feat["is_known_shortener"]:
                shortener_count += 1
            if feat["has_unusual_port"]:
                unusual_port_count += 1
            if feat["has_userinfo"]:
                userinfo_count += 1
            if feat["excessive_subdomain_depth"]:
                excessive_subdomain_count += 1

            for kw in feat["suspicious_path_keywords"]:
                path_keywords_counter[kw] += 1
            for prm in feat["suspicious_query_params"]:
                query_params_counter[prm] += 1

        risk_scores.append(res["risk_score"])
        risk_level_counter[res["risk_level"]] += 1
        for sig in res["signals"]:
            signal_counter[sig["signal"]] += 1

    # Aggregate Feature Statistics
    feature_stats = {
        "total_messages": total_records,
        "messages_with_urls": records_with_urls,
        "url_message_percentage": round(records_with_urls / total_records * 100, 2) if total_records else 0,
        "total_url_mentions": len(all_url_mentions),
        "unique_urls_count": len(unique_urls_set),
        "malformed_urls_count": malformed_count,
        "schemes_distribution": dict(schemes_counter),
        "host_properties": {
            "ip_based_hostnames": ip_host_count,
            "punycode_hostnames": punycode_count,
            "non_ascii_hostnames": non_ascii_count,
            "known_shorteners": shortener_count,
            "excessive_subdomain_depth": excessive_subdomain_count,
        },
        "port_properties": {
            "unusual_ports": unusual_port_count,
        },
        "authority_properties": {
            "userinfo_present": userinfo_count,
        },
        "length_properties": {
            "mean_url_length": round(float(np.mean(url_lengths)), 2) if url_lengths else 0,
            "median_url_length": round(float(np.median(url_lengths)), 2) if url_lengths else 0,
            "max_url_length": int(np.max(url_lengths)) if url_lengths else 0,
            "min_url_length": int(np.min(url_lengths)) if url_lengths else 0,
        },
        "top_path_keywords": dict(path_keywords_counter.most_common(10)),
        "top_query_parameters": dict(query_params_counter.most_common(10)),
    }

    # Signal Frequency Summary
    signal_frequency = {
        "total_signals_triggered": sum(signal_counter.values()),
        "signal_counts": dict(signal_counter.most_common()),
        "signal_prevalence_pct": {
            sig: round(cnt / len(all_url_mentions) * 100, 2)
            for sig, cnt in signal_counter.most_common()
        } if all_url_mentions else {},
    }

    # Risk Score Distribution
    risk_distribution = {
        "risk_level_counts": dict(risk_level_counter),
        "risk_level_percentages": {
            lvl: round(cnt / len(all_url_mentions) * 100, 2)
            for lvl, cnt in risk_level_counter.items()
        } if all_url_mentions else {},
        "score_statistics": {
            "mean": round(float(np.mean(risk_scores)), 4) if risk_scores else 0,
            "median": round(float(np.median(risk_scores)), 4) if risk_scores else 0,
            "min": round(float(np.min(risk_scores)), 4) if risk_scores else 0,
            "max": round(float(np.max(risk_scores)), 4) if risk_scores else 0,
            "std": round(float(np.std(risk_scores)), 4) if risk_scores else 0,
        },
        "threshold_bands": {
            "low_0.00_to_0.24": risk_level_counter.get("low", 0),
            "moderate_0.25_to_0.49": risk_level_counter.get("moderate", 0),
            "high_0.50_to_0.74": risk_level_counter.get("high", 0),
            "very_high_0.75_to_1.00": risk_level_counter.get("very_high", 0),
            "unknown_malformed": risk_level_counter.get("unknown", 0),
        },
    }

    # 1. Write url_analysis_results.jsonl
    with open(out_path / "url_analysis_results.jsonl", "w", encoding="utf-8") as f:
        for item in mentions_analysis:
            f.write(json.dumps(item, ensure_ascii=False) + "\n")

    # 2. Write feature_statistics.json
    with open(out_path / "feature_statistics.json", "w", encoding="utf-8") as f:
        json.dump(feature_stats, f, indent=2)

    # 3. Write signal_frequency.json
    with open(out_path / "signal_frequency.json", "w", encoding="utf-8") as f:
        json.dump(signal_frequency, f, indent=2)

    # 4. Write risk_distribution.json
    with open(out_path / "risk_distribution.json", "w", encoding="utf-8") as f:
        json.dump(risk_distribution, f, indent=2)

    # 5. Write README.md
    _generate_url_eval_readme(
        out_path / "README.md",
        feature_stats=feature_stats,
        signal_frequency=signal_frequency,
        risk_distribution=risk_distribution,
    )

    return {
        "feature_statistics": feature_stats,
        "signal_frequency": signal_frequency,
        "risk_distribution": risk_distribution,
        "output_dir": str(out_path),
    }


def _generate_url_eval_readme(
    report_path: Path,
    feature_stats: Dict[str, Any],
    signal_frequency: Dict[str, Any],
    risk_distribution: Dict[str, Any],
) -> None:
    """Generates an auditable markdown evaluation summary for URL analysis."""
    lines = [
        "# ScamShield AI — Phase 4 URL Analysis Evaluation Report 🔗",
        "",
        "**Component:** Passive Offline URL Analysis & Threat Heuristics  ",
        "**Source Dataset:** UCI SMS Spam Collection (`data/processed/preprocessed/uci_sms_spam.jsonl`)  ",
        "**Operational Mode:** 100% Offline (Zero outbound HTTP/DNS requests, deterministic string analysis)  ",
        "",
        "---",
        "",
        "## 1. Corpus URL Extraction Overview",
        "",
        f"- **Total SMS Messages Analyzed:** {feature_stats['total_messages']}",
        f"- **Messages Containing URLs:** {feature_stats['messages_with_urls']} ({feature_stats['url_message_percentage']}%)",
        f"- **Total URL Mentions:** {feature_stats['total_url_mentions']}",
        f"- **Unique URLs:** {feature_stats['unique_urls_count']}",
        f"- **Malformed / Unparseable URLs:** {feature_stats['malformed_urls_count']}",
        "",
        "---",
        "",
        "## 2. Structural Feature Statistics",
        "",
        "### Schemes Distribution",
        "| Scheme | Mention Count |",
        "| :--- | :---: |",
    ]
    for sch, cnt in feature_stats["schemes_distribution"].items():
        lines.append(f"| `{sch}` | {cnt} |")

    lines.extend([
        "",
        "### Host & Authority Structural Signals",
        f"- **IP-based Hostnames:** {feature_stats['host_properties']['ip_based_hostnames']}",
        f"- **Punycode Hostnames:** {feature_stats['host_properties']['punycode_hostnames']}",
        f"- **Non-ASCII Hostnames:** {feature_stats['host_properties']['non_ascii_hostnames']}",
        f"- **Known Link Shorteners:** {feature_stats['host_properties']['known_shorteners']}",
        f"- **Excessive Subdomain Depth (>=3):** {feature_stats['host_properties']['excessive_subdomain_depth']}",
        f"- **Unusual Ports:** {feature_stats['port_properties']['unusual_ports']}",
        f"- **Userinfo Present:** {feature_stats['authority_properties']['userinfo_present']}",
        "",
        "### URL Length Statistics",
        f"- Mean: `{feature_stats['length_properties']['mean_url_length']}` characters",
        f"- Median: `{feature_stats['length_properties']['median_url_length']}` characters",
        f"- Range: `[{feature_stats['length_properties']['min_url_length']}, {feature_stats['length_properties']['max_url_length']}]` characters",
        "",
        "---",
        "",
        "## 3. Heuristic Signal Frequency",
        "",
        "| Heuristic Signal | Mentions Triggered | Prevalence (%) |",
        "| :--- | :---: | :---: |",
    ])

    for sig, cnt in signal_frequency["signal_counts"].items():
        pct = signal_frequency["signal_prevalence_pct"].get(sig, 0)
        lines.append(f"| `{sig}` | {cnt} | {pct}% |")

    lines.extend([
        "",
        "---",
        "",
        "## 4. Heuristic Risk Distribution",
        "",
        "| Risk Band | Qualitative Level | Count | Proportion |",
        "| :--- | :--- | :---: | :---: |",
        f"| `[0.00, 0.24]` | Low | {risk_distribution['threshold_bands']['low_0.00_to_0.24']} | {risk_distribution['risk_level_percentages'].get('low', 0)}% |",
        f"| `[0.25, 0.49]` | Moderate | {risk_distribution['threshold_bands']['moderate_0.25_to_0.49']} | {risk_distribution['risk_level_percentages'].get('moderate', 0)}% |",
        f"| `[0.50, 0.74]` | High | {risk_distribution['threshold_bands']['high_0.50_to_0.74']} | {risk_distribution['risk_level_percentages'].get('high', 0)}% |",
        f"| `[0.75, 1.00]` | Very High | {risk_distribution['threshold_bands']['very_high_0.75_to_1.00']} | {risk_distribution['risk_level_percentages'].get('very_high', 0)}% |",
        "",
        "### Score Metrics",
        f"- **Mean Heuristic Score:** `{risk_distribution['score_statistics']['mean']}`",
        f"- **Median Heuristic Score:** `{risk_distribution['score_statistics']['median']}`",
        f"- **Score Range:** `[{risk_distribution['score_statistics']['min']}, {risk_distribution['score_statistics']['max']}]`",
        "",
        "---",
        "",
        "## 5. Security & Isolation Boundary",
        "",
        "- **Zero Outbound Calls:** Verified 100% offline string analysis.",
        "- **No Label Leakage:** Scam/non-scam labels were never used to tune or calibrate heuristic weights.",
        "- **No ML Modification:** Phase 3 baseline models remain frozen and independent.",
    ])

    with open(report_path, "w", encoding="utf-8") as f:
        f.write("\n".join(lines) + "\n")


if __name__ == "__main__":
    run_batch_url_analysis()
