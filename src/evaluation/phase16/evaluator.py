"""End-to-End Real-World Evaluation Runner for ScamShield AI Phase 16.

Executes the complete production pipeline via InvestigationService.investigate()
on the independent 90-sample validation corpus.
Computes comprehensive metrics across classification, subgroups, tactics,
semantic similarity, novelty, URL, OCR/visual, performance, and security.
"""

from collections import defaultdict
import json
import os
from pathlib import Path
import time
from typing import Any, Dict, List, Optional, Set, Tuple

from src.app.schemas import InvestigationInput, InvestigationReport
from src.app.service import InvestigationService


class Phase16Evaluator:
    """End-to-end evaluation engine for Phase 16."""

    def __init__(self, base_dir: Path):
        self.base_dir = base_dir
        self.manifest_path = base_dir / "data" / "evaluation" / "phase16" / "phase16_dataset_manifest.jsonl"
        self.results_path = base_dir / "data" / "evaluation" / "phase16" / "evaluation_results.json"
        self.service: Optional[InvestigationService] = None

    def load_manifest(self) -> List[Dict[str, Any]]:
        """Loads Phase 16 dataset manifest."""
        samples = []
        with open(self.manifest_path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line:
                    samples.append(json.loads(line))
        return samples

    def run_evaluation(self) -> Dict[str, Any]:
        """Runs all 90 samples through InvestigationService.investigate()."""
        print(f"Loading manifest from {self.manifest_path}...")
        samples = self.load_manifest()
        print(f"Loaded {len(samples)} samples.")

        # Measure Process Cold Start / Initialization
        t_init_start = time.perf_counter()
        self.service = InvestigationService(enable_semantic=True, default_provider="mock")
        init_time_ms = (time.perf_counter() - t_init_start) * 1000

        # Measure Warmup
        warmup_timings = self.service.warmup()

        records = []
        latencies = []
        first_investigation_ms = None

        print("Executing end-to-end investigations...")
        for idx, s in enumerate(samples):
            s_id = s["sample_id"]
            itype = s["input_type"]
            text = s.get("text")
            urls = s.get("urls", [])
            primary_url = urls[0] if urls else None
            img_path = s.get("image_path")

            # Route to InvestigationInput
            inv_input = InvestigationInput(
                text=text if itype != "url" else None,
                url=primary_url or (text if itype == "url" else None),
                image_path=img_path if itype == "image" else None,
                case_id=s_id,
                enable_semantic=True,
            )

            t0 = time.perf_counter()
            report = self.service.investigate(inv_input)
            latency_ms = (time.perf_counter() - t0) * 1000
            latencies.append(latency_ms)

            if idx == 0:
                first_investigation_ms = latency_ms

            # Extract fields
            assessment = report.assessment
            status = assessment.get("status", "unknown")
            ev_level = assessment.get("evidence_level", "unknown")
            consistency = assessment.get("signal_consistency", "unknown")
            detected_tactics = report.detected_tactics
            url_findings = report.url_findings
            semantic_context = report.semantic_context
            visual_observations = report.visual_observations
            ocr_text = report.ocr_text
            explanation = report.explanation
            warnings = report.warnings

            records.append({
                "sample_id": s_id,
                "case_group": s["case_group"],
                "input_type": s["input_type"],
                "language": s["language"],
                "script": s["script"],
                "ground_truth_label": s["ground_truth_label"],
                "scam_category_if_known": s.get("scam_category_if_known"),
                "known_unknown_status": s.get("known_unknown_status"),
                "primary_tactics": s.get("primary_tactics", []),
                "secondary_tactics": s.get("secondary_tactics", []),
                "requested_action": s.get("requested_action"),
                "impersonated_entity": s.get("impersonated_entity"),
                "urgency_level": s.get("urgency_level"),
                "status": status,
                "evidence_level": ev_level,
                "signal_consistency": consistency,
                "detected_tactics": detected_tactics,
                "url_findings_count": len(url_findings),
                "semantic_similarity": semantic_context.get("max_similarity"),
                "semantic_top_match": semantic_context.get("top_match_id"),
                "novelty_score": semantic_context.get("novelty_score"),
                "ocr_extracted": bool(ocr_text),
                "ocr_text_length": len(ocr_text) if ocr_text else 0,
                "visual_observations_count": len(visual_observations),
                "explanation_available": report.explanation_available,
                "warnings": warnings,
                "latency_ms": latency_ms,
                "timings_ms": report.timings_ms,
            })

        metrics = self.compute_metrics(records, latencies, init_time_ms, first_investigation_ms, warmup_timings)

        # Save raw results and metrics
        out_payload = {
            "metadata": {
                "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                "sample_count": len(records),
                "init_time_ms": init_time_ms,
                "warmup_timings": warmup_timings,
            },
            "metrics": metrics,
            "records": records,
        }

        self.results_path.parent.mkdir(parents=True, exist_ok=True)
        with open(self.results_path, "w", encoding="utf-8") as f:
            json.dump(out_payload, f, indent=2)

        print(f"Saved evaluation results to {self.results_path}")
        return out_payload

    def compute_metrics(
        self,
        records: List[Dict[str, Any]],
        latencies: List[float],
        init_time_ms: float,
        first_investigation_ms: float,
        warmup_timings: Dict[str, float],
    ) -> Dict[str, Any]:
        """Calculates all Phase 16 core metrics."""
        total = len(records)
        scam_gt_count = sum(1 for r in records if r["ground_truth_label"] == "scam")
        non_scam_gt_count = sum(1 for r in records if r["ground_truth_label"] == "non_scam")

        # 1. Status Distribution
        status_dist = defaultdict(lambda: {"total": 0, "scam": 0, "non_scam": 0})
        for r in records:
            st = r["status"]
            gt = r["ground_truth_label"]
            status_dist[st]["total"] += 1
            status_dist[st][gt] += 1

        # 2. Strict Binary Classification (likely_scam = positive, others = negative)
        tp = sum(1 for r in records if r["ground_truth_label"] == "scam" and r["status"] == "likely_scam")
        fp = sum(1 for r in records if r["ground_truth_label"] == "non_scam" and r["status"] == "likely_scam")
        tn = sum(1 for r in records if r["ground_truth_label"] == "non_scam" and r["status"] != "likely_scam")
        fn = sum(1 for r in records if r["ground_truth_label"] == "scam" and r["status"] != "likely_scam")

        accuracy = (tp + tn) / total if total > 0 else 0.0
        precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
        recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0
        f1 = (2 * precision * recall) / (precision + recall) if (precision + recall) > 0 else 0.0
        fpr = fp / (fp + tn) if (fp + tn) > 0 else 0.0
        fnr = fn / (fn + tp) if (fn + tp) > 0 else 0.0

        # Hard-Negative FPR (C3 group)
        c3_records = [r for r in records if r["case_group"] == "C3_hard_negatives"]
        c3_fp = sum(1 for r in c3_records if r["status"] == "likely_scam")
        c3_mixed = sum(1 for r in c3_records if r["status"] == "mixed_signals")
        c3_tn = sum(1 for r in c3_records if r["status"] == "likely_non_scam")
        c3_fpr = c3_fp / len(c3_records) if c3_records else 0.0

        # 3. Subgroup Breakdown
        subgroups = {}
        # Languages
        for lang in ["en", "hi", "hinglish", "mixed"]:
            sub_recs = [r for r in records if r["language"] == lang]
            sub_scam = [r for r in sub_recs if r["ground_truth_label"] == "scam"]
            sub_non = [r for r in sub_recs if r["ground_truth_label"] == "non_scam"]
            sub_tp = sum(1 for r in sub_scam if r["status"] == "likely_scam")
            sub_fp = sum(1 for r in sub_non if r["status"] == "likely_scam")
            sub_tn = sum(1 for r in sub_non if r["status"] != "likely_scam")
            sub_fn = sum(1 for r in sub_scam if r["status"] != "likely_scam")
            sub_acc = (sub_tp + sub_tn) / len(sub_recs) if sub_recs else 0.0
            sub_rec = sub_tp / len(sub_scam) if sub_scam else 0.0
            sub_prec = sub_tp / (sub_tp + sub_fp) if (sub_tp + sub_fp) > 0 else 0.0
            sub_f1 = (2 * sub_prec * sub_rec) / (sub_prec + sub_rec) if (sub_prec + sub_rec) > 0 else 0.0
            subgroups[f"lang_{lang}"] = {
                "count": len(sub_recs),
                "scam_count": len(sub_scam),
                "non_scam_count": len(sub_non),
                "tp": sub_tp,
                "fp": sub_fp,
                "tn": sub_tn,
                "fn": sub_fn,
                "accuracy": sub_acc,
                "precision": sub_prec,
                "recall": sub_rec,
                "f1": sub_f1,
            }

        # Case Groups C1 to C8
        for grp in [
            "C1_common_scams", "C2_unknown_emerging", "C3_hard_negatives",
            "C4_multilingual", "C5_obfuscated", "C6_url_cases",
            "C7_screenshot_cases", "C8_adversarial_injection"
        ]:
            g_recs = [r for r in records if r["case_group"] == grp]
            g_scam = [r for r in g_recs if r["ground_truth_label"] == "scam"]
            g_non = [r for r in g_recs if r["ground_truth_label"] == "non_scam"]
            g_tp = sum(1 for r in g_scam if r["status"] == "likely_scam")
            g_fp = sum(1 for r in g_non if r["status"] == "likely_scam")
            g_tn = sum(1 for r in g_non if r["status"] != "likely_scam")
            g_fn = sum(1 for r in g_scam if r["status"] != "likely_scam")
            g_rec = g_tp / len(g_scam) if g_scam else 0.0
            g_acc = (g_tp + g_tn) / len(g_recs) if g_recs else 0.0
            subgroups[grp] = {
                "count": len(g_recs),
                "scam_count": len(g_scam),
                "non_scam_count": len(g_non),
                "tp": g_tp,
                "fp": g_fp,
                "tn": g_tn,
                "fn": g_fn,
                "recall": g_rec,
                "accuracy": g_acc,
            }

        # 4. Tactic Metrics
        tactic_tp = 0
        tactic_fp = 0
        tactic_fn = 0
        exact_match_count = 0
        tactic_stats = defaultdict(lambda: {"tp": 0, "fp": 0, "fn": 0})

        for r in records:
            gt_tactics = set(r["primary_tactics"] + r["secondary_tactics"])
            pred_tactics = set(r["detected_tactics"])

            if gt_tactics == pred_tactics:
                exact_match_count += 1

            for t in pred_tactics:
                if t in gt_tactics:
                    tactic_tp += 1
                    tactic_stats[t]["tp"] += 1
                else:
                    tactic_fp += 1
                    tactic_stats[t]["fp"] += 1

            for t in gt_tactics:
                if t not in pred_tactics:
                    tactic_fn += 1
                    tactic_stats[t]["fn"] += 1

        t_prec = tactic_tp / (tactic_tp + tactic_fp) if (tactic_tp + tactic_fp) > 0 else 0.0
        t_rec = tactic_tp / (tactic_tp + tactic_fn) if (tactic_tp + tactic_fn) > 0 else 0.0
        t_f1 = (2 * t_prec * t_rec) / (t_prec + t_rec) if (t_prec + t_rec) > 0 else 0.0
        exact_set_match_rate = exact_match_count / total if total > 0 else 0.0

        # 5. Image & OCR Metrics (C7)
        c7_recs = [r for r in records if r["case_group"] == "C7_screenshot_cases"]
        ocr_success_count = sum(1 for r in c7_recs if r["ocr_extracted"])
        ocr_success_rate = ocr_success_count / len(c7_recs) if c7_recs else 0.0

        # 6. Novelty / Unknown Threat Recall (C2)
        c2_recs = [r for r in records if r["case_group"] == "C2_unknown_emerging"]
        c2_tp = sum(1 for r in c2_recs if r["status"] == "likely_scam")
        c2_mixed = sum(1 for r in c2_recs if r["status"] == "mixed_signals")
        unknown_threat_recall = c2_tp / len(c2_recs) if c2_recs else 0.0
        unknown_threat_flagged_rate = (c2_tp + c2_mixed) / len(c2_recs) if c2_recs else 0.0

        # 7. Adversarial Containment (C8)
        c8_recs = [r for r in records if r["case_group"] == "C8_adversarial_injection"]
        # Containment means it did NOT get marked as safe / likely_non_scam due to injection
        c8_contained = sum(1 for r in c8_recs if r["status"] != "likely_non_scam")
        c8_containment_rate = c8_contained / len(c8_recs) if c8_recs else 0.0

        # 8. Latency Profiling
        sorted_latencies = sorted(latencies)
        p50 = sorted_latencies[int(len(sorted_latencies) * 0.50)]
        p95 = sorted_latencies[int(len(sorted_latencies) * 0.95)]
        mean_latency = sum(latencies) / len(latencies) if latencies else 0.0

        return {
            "sample_counts": {
                "total": total,
                "scam": scam_gt_count,
                "non_scam": non_scam_gt_count,
            },
            "classification": {
                "tp": tp,
                "fp": fp,
                "tn": tn,
                "fn": fn,
                "accuracy": accuracy,
                "precision": precision,
                "recall": recall,
                "f1": f1,
                "fpr": fpr,
                "fnr": fnr,
            },
            "hard_negative_fpr": {
                "total_hard_negatives": len(c3_records),
                "fp_count": c3_fp,
                "mixed_count": c3_mixed,
                "tn_count": c3_tn,
                "fpr": c3_fpr,
            },
            "status_distribution": {k: dict(v) for k, v in status_dist.items()},
            "subgroups": subgroups,
            "tactic_metrics": {
                "micro_precision": t_prec,
                "micro_recall": t_rec,
                "micro_f1": t_f1,
                "exact_set_match_rate": exact_set_match_rate,
                "per_tactic": {k: dict(v) for k, v in tactic_stats.items()},
            },
            "ocr_metrics": {
                "total_screenshots": len(c7_recs),
                "ocr_success_count": ocr_success_count,
                "ocr_success_rate": ocr_success_rate,
            },
            "unknown_threat": {
                "c2_count": len(c2_recs),
                "tp_likely_scam": c2_tp,
                "mixed_signals": c2_mixed,
                "strict_recall": unknown_threat_recall,
                "flagged_rate": unknown_threat_flagged_rate,
            },
            "security_containment": {
                "c8_count": len(c8_recs),
                "contained_count": c8_contained,
                "containment_rate": c8_containment_rate,
            },
            "performance": {
                "init_time_ms": init_time_ms,
                "first_investigation_ms": first_investigation_ms,
                "mean_latency_ms": mean_latency,
                "p50_latency_ms": p50,
                "p95_latency_ms": p95,
                "warmup_timings_ms": warmup_timings,
            },
        }


if __name__ == "__main__":
    root = Path(__file__).resolve().parents[3]
    evaluator = Phase16Evaluator(root)
    results = evaluator.run_evaluation()
    print("Phase 16 Evaluation Run Complete!")
    metrics = results["metrics"]
    print(f"Accuracy: {metrics['classification']['accuracy']:.4f}")
    print(f"Scam Precision: {metrics['classification']['precision']:.4f}")
    print(f"Scam Recall: {metrics['classification']['recall']:.4f}")
    print(f"Scam F1: {metrics['classification']['f1']:.4f}")
    print(f"Hard-Negative FPR: {metrics['hard_negative_fpr']['fpr']:.4f}")
