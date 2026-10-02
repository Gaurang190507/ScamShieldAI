"""Evaluation engine for ScamShield AI Phase 12 Real-World Robustness & Generalization.

Coordinates comprehensive, reproducible evaluation across:
1. Phase 3 Text Baseline Classifier (TF-IDF + Logistic Regression)
2. Phase 4 Passive URL Scanner (offline structural heuristics)
3. Phase 6 Scam Tactic Detector (behavioral rules + evidence spans)
4. Phase 7 Semantic Similarity & Novelty Detector (offline reference index)
5. Phase 8 Multi-Signal Risk Aggregator (deterministic rule engine)
6. Phase 11 Investigation Service (end-to-end multi-modal orchestration)

HARD CONSTRAINTS ENFORCED:
- Zero outbound network calls (100% offline).
- Zero threshold tuning or model retraining.
- Strict isolation of Phase 12 evaluation datasets.
"""

from collections import defaultdict
import json
from pathlib import Path
import time
from typing import Any, Dict, List, Optional, Set, Tuple, Union

import numpy as np

from src.aggregation.pipeline import CaseAssessmentPipeline
from src.aggregation.schemas import CaseAssessmentResult
from src.app.schemas import InvestigationInput, InvestigationReport
from src.app.service import InvestigationService
from src.models.baseline_classifier import BaselineTextClassifier
from src.ocr.extractor import OCRTextExtractor
from src.ocr.ocr_engine import FixtureOCREngine
from src.semantic.analyzer import SemanticAnalyzer
from src.tactics.tactic_detector import TacticDetector
from src.url_analysis.url_scanner import URLScanner


def _calc_binary_metrics(tp: int, tn: int, fp: int, fn: int) -> Dict[str, Any]:
    """Calculates standard classification metrics from confusion counts."""
    total = tp + tn + fp + fn
    accuracy = round((tp + tn) / total, 4) if total > 0 else 0.0
    precision = round(tp / (tp + fp), 4) if (tp + fp) > 0 else 0.0
    recall = round(tp / (tp + fn), 4) if (tp + fn) > 0 else 0.0
    f1 = round(2 * precision * recall / (precision + recall), 4) if (precision + recall) > 0 else 0.0
    fpr = round(fp / (fp + tn), 4) if (fp + tn) > 0 else 0.0
    fnr = round(fn / (fn + tp), 4) if (fn + tp) > 0 else 0.0
    return {
        "tp": tp,
        "tn": tn,
        "fp": fp,
        "fn": fn,
        "total": total,
        "accuracy": accuracy,
        "precision": precision,
        "recall": recall,
        "f1": f1,
        "fpr": fpr,
        "fnr": fnr,
    }


class Phase12Evaluator:
    """Evaluates frozen ScamShield components on modern, real-world benchmarks."""

    def __init__(
        self,
        base_dir: Optional[Union[str, Path]] = None,
        pipeline: Optional[CaseAssessmentPipeline] = None,
        service: Optional[InvestigationService] = None,
    ):
        """Initializes evaluator and resolves dataset paths.

        Args:
            base_dir: Root directory of project.
            pipeline: Pre-configured CaseAssessmentPipeline.
            service: Pre-configured InvestigationService.
        """
        self.root_dir = Path(base_dir).resolve() if base_dir else Path(__file__).resolve().parents[3]
        self.eval_data_dir = self.root_dir / "data" / "evaluation" / "phase12"

        # Initialize pipeline and service
        self.pipeline = pipeline or CaseAssessmentPipeline(enable_semantic=True)

        # Initialize InvestigationService with fixture OCR engine if available
        fixtures_manifest = self.root_dir / "tests" / "fixtures" / "images" / "manifest.json"
        if fixtures_manifest.is_file():
            ocr_engine = FixtureOCREngine(manifest_path=fixtures_manifest)
            ocr_extractor = OCRTextExtractor(ocr_engine=ocr_engine)
        else:
            ocr_extractor = OCRTextExtractor()

        self.service = service or InvestigationService(
            pipeline=self.pipeline,
            ocr_extractor=ocr_extractor,
            enable_semantic=True,
            default_provider="mock",
        )

        # Datasets container
        self.datasets: Dict[str, List[Dict[str, Any]]] = {}
        self.load_datasets()

    def _load_jsonl(self, rel_path: str) -> List[Dict[str, Any]]:
        """Loads records from a JSONL file relative to Phase 12 eval directory."""
        file_path = self.eval_data_dir / rel_path
        if not file_path.is_file():
            raise FileNotFoundError(f"Required Phase 12 evaluation dataset not found: {file_path}")
        records: List[Dict[str, Any]] = []
        with open(file_path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line:
                    records.append(json.loads(line))
        return records

    def load_datasets(self) -> None:
        """Loads all Phase 12 evaluation datasets into memory."""
        self.datasets["real_world"] = self._load_jsonl("real_world/real_world_cases.jsonl")
        self.datasets["modern_indian_scams"] = self._load_jsonl("modern_scam_patterns/modern_indian_scams.jsonl")
        self.datasets["hard_negatives"] = self._load_jsonl("hard_negatives/hard_negatives.jsonl")
        self.datasets["multilingual"] = self._load_jsonl("multilingual/multilingual_cases.jsonl")
        self.datasets["obfuscated"] = self._load_jsonl("obfuscated/obfuscated_cases.jsonl")
        self.datasets["novel_patterns"] = self._load_jsonl("novel_patterns/novel_scam_patterns.jsonl")
        self.datasets["urls"] = self._load_jsonl("urls/url_benchmark.jsonl")
        self.datasets["screenshots"] = self._load_jsonl("screenshots/screenshot_cases.jsonl")

    # =========================================================================
    # 1. CLASSIFICATION EVALUATION (PHASE 3 BASELINE)
    # =========================================================================

    def evaluate_classification(self) -> Dict[str, Any]:
        """Evaluates Phase 3 text classifier across full benchmark and subsets."""
        classifier = self.pipeline.classifier
        if classifier is None:
            return {"error": "Phase 3 classifier not initialized"}

        real_world_cases = self.datasets["real_world"]

        subsets: Dict[str, List[Dict[str, Any]]] = {
            "overall": real_world_cases,
            "scam_cases": [c for c in real_world_cases if c["label"] == "scam"],
            "non_scam_cases": [c for c in real_world_cases if c["label"] == "non_scam"],
            "hard_negatives": self.datasets["hard_negatives"],
            "modern_indian_scams": self.datasets["modern_indian_scams"],
            "multilingual_all": self.datasets["multilingual"],
            "multilingual_hindi": [c for c in self.datasets["multilingual"] if c.get("language") == "hi"],
            "multilingual_hinglish": [c for c in self.datasets["multilingual"] if c.get("language") == "hi-Latn"],
            "obfuscated": self.datasets["obfuscated"],
            "novel_patterns": self.datasets["novel_patterns"],
        }

        results: Dict[str, Any] = {}
        all_predictions: List[Dict[str, Any]] = []

        for subset_name, cases in subsets.items():
            tp = tn = fp = fn = 0
            probabilities: List[float] = []

            for case in cases:
                text = case.get("text", "")
                ground_truth = case["label"]
                pred = classifier.predict(text)
                pred_label = pred["label"]
                prob = float(pred["probability"])
                probabilities.append(prob)

                if ground_truth == "scam" and pred_label == "scam":
                    tp += 1
                elif ground_truth == "non_scam" and pred_label == "non_scam":
                    tn += 1
                elif ground_truth == "non_scam" and pred_label == "scam":
                    fp += 1
                elif ground_truth == "scam" and pred_label == "non_scam":
                    fn += 1

                if subset_name == "overall":
                    sid = case.get("sample_id") or case.get("case_id", "unknown")
                    all_predictions.append({
                        "sample_id": sid,
                        "scam_category": case.get("scam_category", "unknown"),
                        "ground_truth": ground_truth,
                        "pred_label": pred_label,
                        "probability": round(prob, 4),
                        "text_preview": text[:80] + ("..." if len(text) > 80 else ""),
                    })

            metrics = _calc_binary_metrics(tp, tn, fp, fn)
            metrics["mean_probability"] = round(float(np.mean(probabilities)), 4) if probabilities else 0.0
            metrics["median_probability"] = round(float(np.median(probabilities)), 4) if probabilities else 0.0
            results[subset_name] = metrics

        results["sample_predictions"] = all_predictions
        return results

    # =========================================================================
    # 2. TACTIC DETECTION EVALUATION (PHASE 6)
    # =========================================================================

    def evaluate_tactics(self) -> Dict[str, Any]:
        """Evaluates Phase 6 deterministic tactic detector on expected tactic annotations."""
        tactic_detector = self.pipeline.tactic_detector

        evaluated_cases: List[Dict[str, Any]] = []
        for case in self.datasets["real_world"]:
            if "tactics" in case and case["tactics"]:
                evaluated_cases.append(case)

        per_tactic_counts: Dict[str, Dict[str, int]] = defaultdict(lambda: {"tp": 0, "fp": 0, "fn": 0})
        exact_matches = 0
        total_cases = len(evaluated_cases)
        macro_precisions: List[float] = []
        macro_recalls: List[float] = []

        detailed_results: List[Dict[str, Any]] = []

        total_gold_tactics = 0
        total_pred_tactics = 0
        total_correct_tactics = 0

        for case in evaluated_cases:
            text = case.get("text", "")
            expected_set: Set[str] = set(case.get("tactics", []))
            res = tactic_detector.detect(text)
            detected_set: Set[str] = {t.tactic for t in res.tactics}

            if detected_set == expected_set:
                exact_matches += 1

            intersection = detected_set.intersection(expected_set)
            total_gold_tactics += len(expected_set)
            total_pred_tactics += len(detected_set)
            total_correct_tactics += len(intersection)

            # Update per-tactic
            all_tactics = expected_set.union(detected_set)
            for t in all_tactics:
                if t in detected_set and t in expected_set:
                    per_tactic_counts[t]["tp"] += 1
                elif t in detected_set and t not in expected_set:
                    per_tactic_counts[t]["fp"] += 1
                elif t not in detected_set and t in expected_set:
                    per_tactic_counts[t]["fn"] += 1

            # Case-level P & R
            case_p = len(intersection) / len(detected_set) if detected_set else (1.0 if not expected_set else 0.0)
            case_r = len(intersection) / len(expected_set) if expected_set else 1.0
            macro_precisions.append(case_p)
            macro_recalls.append(case_r)

            sid = case.get("sample_id") or case.get("case_id", "unknown")
            detailed_results.append({
                "sample_id": sid,
                "expected": sorted(list(expected_set)),
                "detected": sorted(list(detected_set)),
                "exact_match": detected_set == expected_set,
                "evidence_count": len(res.tactics),
            })

        # Micro metrics
        micro_p = round(total_correct_tactics / total_pred_tactics, 4) if total_pred_tactics > 0 else 0.0
        micro_r = round(total_correct_tactics / total_gold_tactics, 4) if total_gold_tactics > 0 else 0.0
        micro_f1 = round(2 * micro_p * micro_r / (micro_p + micro_r), 4) if (micro_p + micro_r) > 0 else 0.0

        # Macro metrics across cases
        macro_p = round(float(np.mean(macro_precisions)), 4) if macro_precisions else 0.0
        macro_r = round(float(np.mean(macro_recalls)), 4) if macro_recalls else 0.0
        macro_f1 = round(2 * macro_p * macro_r / (macro_p + macro_r), 4) if (macro_p + macro_r) > 0 else 0.0

        exact_match_rate = round(exact_matches / total_cases, 4) if total_cases > 0 else 0.0

        # Per-tactic breakdown
        per_tactic_metrics: Dict[str, Dict[str, Any]] = {}
        for tactic_name, counts in sorted(per_tactic_counts.items()):
            t_tp = counts["tp"]
            t_fp = counts["fp"]
            t_fn = counts["fn"]
            tp_fp = t_tp + t_fp
            tp_fn = t_tp + t_fn
            p = round(t_tp / tp_fp, 4) if tp_fp > 0 else 0.0
            r = round(t_tp / tp_fn, 4) if tp_fn > 0 else 0.0
            f1 = round(2 * p * r / (p + r), 4) if (p + r) > 0 else 0.0
            per_tactic_metrics[tactic_name] = {
                "tp": t_tp,
                "fp": t_fp,
                "fn": t_fn,
                "precision": p,
                "recall": r,
                "f1": f1,
            }

        return {
            "total_evaluated_cases": total_cases,
            "exact_matches": exact_matches,
            "exact_match_rate": exact_match_rate,
            "micro_metrics": {"precision": micro_p, "recall": micro_r, "f1": micro_f1},
            "macro_metrics": {"precision": macro_p, "recall": macro_r, "f1": macro_f1},
            "per_tactic": per_tactic_metrics,
            "detailed_samples": detailed_results,
        }

    # =========================================================================
    # 3. URL SCANNER EVALUATION (PHASE 4)
    # =========================================================================

    def evaluate_urls(self) -> Dict[str, Any]:
        """Evaluates Phase 4 passive URL scanner against the URL benchmark."""
        url_scanner = self.pipeline.url_scanner
        urls_dataset = self.datasets["urls"]

        total_urls = len(urls_dataset)
        tp = tn = fp = fn = 0
        category_breakdown: Dict[str, Dict[str, Any]] = defaultdict(
            lambda: {"total": 0, "detected_suspicious": 0, "correct": 0}
        )
        signal_trigger_counts: Dict[str, int] = defaultdict(int)
        detailed_results: List[Dict[str, Any]] = []

        for item in urls_dataset:
            url_str = item["url"]
            expected_risk = item.get("expected_risk", "low")
            expected_suspicious = expected_risk in ("high", "moderate")

            # Determine functional category
            signals_expected = item.get("expected_signals", [])
            if expected_risk == "low":
                category = "clean_institutional"
            elif "ip_based_hostname" in signals_expected:
                category = "ip_hostname"
            elif ":8080" in url_str or ":8443" in url_str or "non_standard_port" in signals_expected:
                category = "non_standard_port"
            elif "known_shortener" in signals_expected or any(s in url_str for s in ["bit.ly", "tinyurl", "is.gd", "t.co"]):
                category = "shortener"
            elif "punycode_domain" in signals_expected or "xn--" in url_str:
                category = "punycode"
            elif "excessive_subdomains" in signals_expected or url_str.count(".") >= 4:
                category = "deep_subdomain"
            else:
                category = "other_suspicious"

            analysis = url_scanner.analyze_url(url_str)
            risk_score = analysis.get("risk_score", 0.0)
            risk_level = analysis.get("risk_level", "low")
            signals = analysis.get("signals", [])

            is_predicted_suspicious = risk_score >= 0.30 or risk_level in ("medium", "high")

            for s in signals:
                signal_trigger_counts[s.get("signal_name", "unknown")] += 1

            if expected_suspicious and is_predicted_suspicious:
                tp += 1
                correct = True
            elif not expected_suspicious and not is_predicted_suspicious:
                tn += 1
                correct = True
            elif not expected_suspicious and is_predicted_suspicious:
                fp += 1
                correct = False
            else:
                fn += 1
                correct = False

            category_breakdown[category]["total"] += 1
            if is_predicted_suspicious:
                category_breakdown[category]["detected_suspicious"] += 1
            if correct:
                category_breakdown[category]["correct"] += 1

            detailed_results.append({
                "url_id": item["url_id"],
                "url": url_str,
                "category": category,
                "expected_risk": expected_risk,
                "expected_suspicious": expected_suspicious,
                "predicted_suspicious": is_predicted_suspicious,
                "risk_score": risk_score,
                "risk_level": risk_level,
                "signals": [s.get("signal_name") for s in signals],
            })

        metrics = _calc_binary_metrics(tp, tn, fp, fn)

        cat_rates: Dict[str, Dict[str, Any]] = {}
        for cat, stats in category_breakdown.items():
            tot = stats["total"]
            det = stats["detected_suspicious"]
            cor = stats["correct"]
            cat_rates[cat] = {
                "total": tot,
                "detected_suspicious": det,
                "detection_rate": round(det / tot, 4) if tot > 0 else 0.0,
                "accuracy": round(cor / tot, 4) if tot > 0 else 0.0,
            }

        return {
            "total_urls": total_urls,
            "overall_metrics": metrics,
            "category_performance": cat_rates,
            "signal_frequencies": dict(sorted(signal_trigger_counts.items(), key=lambda x: -x[1])),
            "detailed_results": detailed_results,
        }

    # =========================================================================
    # 4. SEMANTIC SIMILARITY & NOVELTY EVALUATION (PHASE 7)
    # =========================================================================

    def evaluate_semantic_novelty(self) -> Dict[str, Any]:
        """Evaluates Phase 7 semantic similarity search and novelty scoring."""
        analyzer = self.pipeline.semantic_analyzer
        if analyzer is None:
            return {"error": "Semantic analyzer not initialized"}

        subsets: Dict[str, List[Dict[str, Any]]] = {
            "modern_indian_scams": self.datasets["modern_indian_scams"],
            "hard_negatives": self.datasets["hard_negatives"],
            "novel_patterns": self.datasets["novel_patterns"],
            "multilingual": self.datasets["multilingual"],
            "obfuscated": self.datasets["obfuscated"],
        }

        results: Dict[str, Any] = {}
        all_evaluations: List[Dict[str, Any]] = []

        for subset_name, cases in subsets.items():
            top1_sims: List[float] = []
            novelty_scores: List[float] = []
            status_counts: Dict[str, int] = defaultdict(int)

            for case in cases:
                text = case.get("text", "")
                sid = case.get("sample_id") or case.get("case_id", "unknown")
                sem_res = analyzer.analyze(text, sample_id=f"eval_{sid}", disallow_same_id=False)
                ana = sem_res.semantic

                top1_sims.append(ana.top_1_similarity)
                novelty_scores.append(ana.semantic_novelty_score)
                status_counts[ana.semantic_status] += 1

                all_evaluations.append({
                    "sample_id": sid,
                    "subset": subset_name,
                    "top_1_sim": round(ana.top_1_similarity, 4),
                    "novelty_score": round(ana.semantic_novelty_score, 4),
                    "semantic_status": ana.semantic_status,
                    "top_neighbor_source": sem_res.neighbors[0].source if sem_res.neighbors else "none",
                    "top_neighbor_label": sem_res.neighbors[0].label if sem_res.neighbors else "none",
                })

            results[subset_name] = {
                "count": len(cases),
                "mean_top1_similarity": round(float(np.mean(top1_sims)), 4) if top1_sims else 0.0,
                "median_top1_similarity": round(float(np.median(top1_sims)), 4) if top1_sims else 0.0,
                "mean_novelty_score": round(float(np.mean(novelty_scores)), 4) if novelty_scores else 0.0,
                "status_distribution": dict(status_counts),
            }

        results["sample_records"] = all_evaluations
        return results

    # =========================================================================
    # 5. MULTI-SIGNAL AGGREGATION EVALUATION (PHASE 8)
    # =========================================================================

    def evaluate_aggregation(self) -> Dict[str, Any]:
        """Evaluates Phase 8 deterministic risk aggregation on real-world cases."""
        cases = self.datasets["real_world"]
        status_by_label: Dict[str, Dict[str, int]] = {
            "scam": defaultdict(int),
            "non_scam": defaultdict(int),
        }
        rule_triggers: Dict[str, int] = defaultdict(int)
        ambiguous_cases: List[Dict[str, Any]] = []
        all_evaluations: List[Dict[str, Any]] = []

        for case in cases:
            text = case.get("text", "")
            gt = case["label"]
            sid = case.get("sample_id") or case.get("case_id", "unknown")
            result: CaseAssessmentResult = self.pipeline.analyze(text, sample_id=sid)

            st = result.assessment.status
            status_by_label[gt][st] += 1

            rule_name = result.audit.final_decision_rule or "unspecified_rule"
            rule_triggers[rule_name] += 1

            eval_entry = {
                "sample_id": sid,
                "ground_truth": gt,
                "status": st,
                "evidence_level": result.assessment.evidence_level,
                "signal_consistency": result.assessment.signal_consistency,
                "evidence_count": len(result.evidence),
                "explanation_summary": result.explanation.summary,
            }
            all_evaluations.append(eval_entry)

            if st in ("mixed_signals", "insufficient_evidence"):
                ambiguous_cases.append({
                    "sample_id": sid,
                    "ground_truth": gt,
                    "status": st,
                    "text": text,
                    "signals": {
                        "text_model": result.signals.get("text_model"),
                        "tactics_count": len(result.signals.get("tactics", [])),
                        "url_signals": len(result.signals.get("url_signals", [])),
                        "semantic": (
                            result.signals.get("semantic", {}).get("semantic_status")
                            if isinstance(result.signals.get("semantic"), dict)
                            else None
                        ),
                    },
                    "reason": result.explanation.reasons,
                })

        return {
            "total_cases": len(cases),
            "scam_status_distribution": dict(status_by_label["scam"]),
            "non_scam_status_distribution": dict(status_by_label["non_scam"]),
            "rule_trigger_distribution": dict(sorted(rule_triggers.items(), key=lambda x: -x[1])),
            "ambiguous_cases_count": len(ambiguous_cases),
            "ambiguous_cases": ambiguous_cases,
            "all_evaluations": all_evaluations,
        }

    # =========================================================================
    # 6. MULTILINGUAL GAPS EVALUATION
    # =========================================================================

    def evaluate_multilingual(self) -> Dict[str, Any]:
        """Evaluates detection capability and vocabulary gaps across languages."""
        multi_cases = self.datasets["multilingual"]
        classifier = self.pipeline.classifier
        vectorizer = classifier.vectorizer if classifier else None

        lang_breakdown: Dict[str, Dict[str, Any]] = {}
        for lang_name, lang_code in [("native_hindi", "hi"), ("romanized_hinglish", "hi-Latn")]:
            cases = [c for c in multi_cases if c.get("language") == lang_code]
            scam_cases = [c for c in cases if c["label"] == "scam"]
            benign_cases = [c for c in cases if c["label"] == "non_scam"]

            oov_tokens = 0
            total_tokens = 0
            if vectorizer is not None:
                vocab = vectorizer.vocabulary_
                for c in cases:
                    words = c["text"].lower().split()
                    total_tokens += len(words)
                    for w in words:
                        if w not in vocab:
                            oov_tokens += 1

            oov_rate = round(oov_tokens / total_tokens, 4) if total_tokens > 0 else 0.0

            tp = tn = fp = fn = 0
            for c in cases:
                pred = classifier.predict(c["text"])
                p_label = pred["label"]
                gt = c["label"]
                if gt == "scam" and p_label == "scam":
                    tp += 1
                elif gt == "non_scam" and p_label == "non_scam":
                    tn += 1
                elif gt == "non_scam" and p_label == "scam":
                    fp += 1
                elif gt == "scam" and p_label == "non_scam":
                    fn += 1

            tactic_hits = 0
            for c in scam_cases:
                t_res = self.pipeline.tactic_detector.detect(c["text"])
                if t_res.tactics:
                    tactic_hits += 1

            tactic_coverage = round(tactic_hits / len(scam_cases), 4) if scam_cases else 0.0

            lang_breakdown[lang_name] = {
                "total_cases": len(cases),
                "scam_cases": len(scam_cases),
                "benign_cases": len(benign_cases),
                "oov_rate": oov_rate,
                "metrics": _calc_binary_metrics(tp, tn, fp, fn),
                "tactic_coverage_on_scams": tactic_coverage,
            }

        return lang_breakdown

    # =========================================================================
    # 7. PERTURBATION CONSISTENCY EVALUATION (OBFUSCATION)
    # =========================================================================

    def evaluate_perturbations(self) -> Dict[str, Any]:
        """Measures degradation and consistency between clean and obfuscated pairs."""
        obf_cases = self.datasets["obfuscated"]
        modern_cases_map = {c["sample_id"]: c for c in self.datasets["modern_indian_scams"]}

        pair_comparisons: List[Dict[str, Any]] = []
        label_flips = 0
        aggregation_status_changes = 0
        jaccard_tactics: List[float] = []
        similarity_drops: List[float] = []

        type_breakdown: Dict[str, Dict[str, Any]] = defaultdict(
            lambda: {"total": 0, "flips": 0, "status_changes": 0, "jaccard_sum": 0.0}
        )

        for obf in obf_cases:
            orig_id = obf["original_sample_id"]
            orig = modern_cases_map.get(orig_id)
            if not orig:
                continue

            clean_text = orig["text"]
            pert_text = obf["text"]
            pert_type = obf.get("transformation_type", "unknown")

            # Phase 3 Text classifier comparison
            pred_clean = self.pipeline.classifier.predict(clean_text)
            pred_pert = self.pipeline.classifier.predict(pert_text)
            prob_diff = round(float(pred_pert["probability"] - pred_clean["probability"]), 4)
            flipped = (pred_clean["label"] != pred_pert["label"])
            if flipped:
                label_flips += 1

            # Phase 6 Tactics comparison
            tact_clean = {t.tactic for t in self.pipeline.tactic_detector.detect(clean_text).tactics}
            tact_pert = {t.tactic for t in self.pipeline.tactic_detector.detect(pert_text).tactics}
            union = tact_clean.union(tact_pert)
            jaccard = round(len(tact_clean.intersection(tact_pert)) / len(union), 4) if union else 1.0
            jaccard_tactics.append(jaccard)

            # Phase 7 Semantic comparison
            sem_clean = self.pipeline.semantic_analyzer.analyze(clean_text, sample_id=f"c_{orig_id}", disallow_same_id=False)
            sem_pert = self.pipeline.semantic_analyzer.analyze(pert_text, sample_id=f"p_{obf['sample_id']}", disallow_same_id=False)
            sim_drop = round(float(sem_clean.semantic.top_1_similarity - sem_pert.semantic.top_1_similarity), 4)
            similarity_drops.append(sim_drop)

            # Phase 8 Aggregation comparison
            agg_clean = self.pipeline.analyze(clean_text, sample_id=orig_id)
            agg_pert = self.pipeline.analyze(pert_text, sample_id=obf["sample_id"])
            agg_status_changed = (agg_clean.assessment.status != agg_pert.assessment.status)
            if agg_status_changed:
                aggregation_status_changes += 1

            type_breakdown[pert_type]["total"] += 1
            if flipped:
                type_breakdown[pert_type]["flips"] += 1
            if agg_status_changed:
                type_breakdown[pert_type]["status_changes"] += 1
            type_breakdown[pert_type]["jaccard_sum"] += jaccard

            pair_comparisons.append({
                "obfuscation_id": obf["sample_id"],
                "original_id": orig_id,
                "transformation_type": pert_type,
                "clean_prob": round(float(pred_clean["probability"]), 4),
                "pert_prob": round(float(pred_pert["probability"]), 4),
                "prob_diff": prob_diff,
                "label_flipped": flipped,
                "clean_tactics": sorted(list(tact_clean)),
                "pert_tactics": sorted(list(tact_pert)),
                "tactic_jaccard": jaccard,
                "sim_drop": sim_drop,
                "clean_agg_status": agg_clean.assessment.status,
                "pert_agg_status": agg_pert.assessment.status,
                "agg_status_changed": agg_status_changed,
            })

        total_pairs = len(pair_comparisons)
        types_summary: Dict[str, Dict[str, Any]] = {}
        for ptype, stats in type_breakdown.items():
            tot = stats["total"]
            types_summary[ptype] = {
                "total": tot,
                "label_flip_rate": round(stats["flips"] / tot, 4) if tot > 0 else 0.0,
                "agg_change_rate": round(stats["status_changes"] / tot, 4) if tot > 0 else 0.0,
                "mean_tactic_jaccard": round(stats["jaccard_sum"] / tot, 4) if tot > 0 else 0.0,
            }

        return {
            "total_pairs": total_pairs,
            "overall_label_flip_rate": round(label_flips / total_pairs, 4) if total_pairs > 0 else 0.0,
            "overall_agg_change_rate": round(aggregation_status_changes / total_pairs, 4) if total_pairs > 0 else 0.0,
            "mean_tactic_jaccard": round(float(np.mean(jaccard_tactics)), 4) if jaccard_tactics else 0.0,
            "mean_similarity_drop": round(float(np.mean(similarity_drops)), 4) if similarity_drops else 0.0,
            "perturbation_type_summary": types_summary,
            "pair_comparisons": pair_comparisons,
        }

    # =========================================================================
    # 8. INVESTIGATION SERVICE INTEGRATION (PHASE 11)
    # =========================================================================

    def evaluate_investigation_service(self) -> Dict[str, Any]:
        """Tests Phase 11 InvestigationService across all 7 input configurations."""
        sample_text = "Electricity cutoff at 9PM due to unpaid bill. Update bill via APK: http://192.168.1.100/bill.apk"
        sample_url = "http://192.168.1.100/bill.apk"
        fixtures_dir = self.root_dir / "tests" / "fixtures" / "images"
        sample_img = fixtures_dir / "scam_kyc_01.png"

        img_available = sample_img.is_file()

        test_configs: List[Tuple[str, InvestigationInput]] = [
            ("text_only", InvestigationInput(text=sample_text)),
            ("url_only", InvestigationInput(url=sample_url)),
            ("combined_text_url", InvestigationInput(text=sample_text, url=sample_url)),
        ]

        if img_available:
            test_configs.extend([
                ("image_only", InvestigationInput(image_path=str(sample_img))),
                ("combined_text_image", InvestigationInput(text=sample_text, image_path=str(sample_img))),
                ("combined_url_image", InvestigationInput(url=sample_url, image_path=str(sample_img))),
                ("combined_all", InvestigationInput(text=sample_text, url=sample_url, image_path=str(sample_img))),
            ])

        config_results: Dict[str, Any] = {}
        for name, inp in test_configs:
            t0 = time.perf_counter()
            report: InvestigationReport = self.service.investigate(inp)
            t_ms = round((time.perf_counter() - t0) * 1000.0, 2)
            config_results[name] = {
                "input_type": report.input_type,
                "status": report.assessment.get("status") if isinstance(report.assessment, dict) else getattr(report.assessment, "status", None),
                "evidence_count": len(report.all_evidence_items),
                "has_explanation": report.explanation_available and bool(report.explanation.get("summary")),
                "has_audit": bool(report.audit),
                "execution_latency_ms": t_ms,
            }

        return {
            "tested_configurations": len(test_configs),
            "image_fixtures_available": img_available,
            "configurations": config_results,
        }

    # =========================================================================
    # 9. PERFORMANCE & LATENCY EVALUATION
    # =========================================================================

    def evaluate_performance(self, repetitions: int = 15) -> Dict[str, Any]:
        """Measures execution latency across pipeline components."""
        sample_text = "Urgent: SBI account blocked due to incomplete KYC. Download SBI APK http://192.168.1.5/sbi.apk immediately."

        clf = self.pipeline.classifier
        url_scan = self.pipeline.url_scanner
        tact = self.pipeline.tactic_detector
        sem = self.pipeline.semantic_analyzer

        # Warm up
        clf.predict(sample_text)
        url_scan.analyze_url("http://192.168.1.5/sbi.apk")
        tact.detect(sample_text)
        if sem:
            sem.analyze(sample_text, sample_id="warmup", disallow_same_id=False)
        self.pipeline.analyze(sample_text, sample_id="warmup")

        def _benchmark(func) -> Dict[str, float]:
            times = []
            for _ in range(repetitions):
                t0 = time.perf_counter()
                func()
                t1 = time.perf_counter()
                times.append((t1 - t0) * 1000.0)
            return {
                "mean_ms": round(float(np.mean(times)), 2),
                "median_ms": round(float(np.median(times)), 2),
                "p95_ms": round(float(np.percentile(times, 95)), 2),
                "p99_ms": round(float(np.percentile(times, 99)), 2),
            }

        component_benchmarks = {
            "phase3_text_classifier": _benchmark(lambda: clf.predict(sample_text)),
            "phase4_url_scanner": _benchmark(lambda: url_scan.analyze_url("http://192.168.1.5/sbi.apk")),
            "phase6_tactic_detector": _benchmark(lambda: tact.detect(sample_text)),
            "phase7_semantic_analyzer": (
                _benchmark(lambda: sem.analyze(sample_text, sample_id="bench", disallow_same_id=False))
                if sem else {"mean_ms": 0.0}
            ),
            "phase8_risk_pipeline": _benchmark(lambda: self.pipeline.analyze(sample_text, sample_id="bench")),
            "phase11_investigation_service": _benchmark(
                lambda: self.service.investigate(InvestigationInput(text=sample_text))
            ),
        }

        return {
            "repetitions": repetitions,
            "components": component_benchmarks,
        }

    # =========================================================================
    # 10. ERROR ANALYSIS COMPILATION
    # =========================================================================

    def compile_error_analysis(self) -> Dict[str, Any]:
        """Compiles detailed failure taxonomy for False Positives, False Negatives, and Ambiguities."""
        clf = self.pipeline.classifier
        real_world_cases = self.datasets["real_world"]

        false_positives: List[Dict[str, Any]] = []
        false_negatives: List[Dict[str, Any]] = []

        for case in real_world_cases:
            text = case.get("text", "")
            gt = case["label"]
            sid = case.get("sample_id") or case.get("case_id", "unknown")
            pred = clf.predict(text)
            p_label = pred["label"]
            prob = float(pred["probability"])

            pipe_res = self.pipeline.analyze(text, sample_id=sid)
            agg_status = pipe_res.assessment.status
            detected_tactics = [t.tactic for t in self.pipeline.tactic_detector.detect(text).tactics]

            if gt == "non_scam" and (p_label == "scam" or agg_status == "likely_scam"):
                false_positives.append({
                    "sample_id": sid,
                    "scam_category": case.get("scam_category", "unknown"),
                    "text_preview": text[:120],
                    "text_pred": p_label,
                    "text_prob": round(prob, 4),
                    "agg_status": agg_status,
                    "detected_tactics": detected_tactics,
                    "primary_failure_mode": "Legitimate institutional alert with urgency/OTP keywords",
                })
            elif gt == "scam" and (p_label == "non_scam" or agg_status == "likely_non_scam"):
                false_negatives.append({
                    "sample_id": sid,
                    "scam_category": case.get("scam_category", "unknown"),
                    "text_preview": text[:120],
                    "text_pred": p_label,
                    "text_prob": round(prob, 4),
                    "agg_status": agg_status,
                    "detected_tactics": detected_tactics,
                    "primary_failure_mode": (
                        "Devanagari OOV text"
                        if case.get("language") == "hi"
                        else "Modern conversational or novel phrasing not in historical UCI corpus"
                    ),
                })

        return {
            "total_false_positives": len(false_positives),
            "false_positives": false_positives,
            "total_false_negatives": len(false_negatives),
            "false_negatives": false_negatives,
        }

    # =========================================================================
    # MASTER EVALUATION RUNNER
    # =========================================================================

    def run_all(self) -> Dict[str, Any]:
        """Runs the complete evaluation suite and returns aggregated results."""
        return {
            "classification": self.evaluate_classification(),
            "tactics": self.evaluate_tactics(),
            "urls": self.evaluate_urls(),
            "semantic": self.evaluate_semantic_novelty(),
            "aggregation": self.evaluate_aggregation(),
            "multilingual": self.evaluate_multilingual(),
            "perturbations": self.evaluate_perturbations(),
            "investigation_service": self.evaluate_investigation_service(),
            "performance": self.evaluate_performance(),
            "error_analysis": self.compile_error_analysis(),
        }
