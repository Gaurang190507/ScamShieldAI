"""Comprehensive evaluation engine for ScamShield AI Phase 13 Generalization.

Coordinates controlled evaluation across:
1. Model A: Frozen Phase 3 Word TF-IDF + Logistic Regression (Control, threshold=0.30)
2. Model B: Subword / Character n-gram TF-IDF + Logistic Regression (threshold=0.55)
3. Model C: Offline Semantic Dense Representation + Logistic Regression (threshold=0.50)
4. Model D: Multimodal Hybrid Fusion (Text + Tactics + URLs, threshold=0.50)
5. Model D Ablation: Text Only vs Text+Tactics vs Text+Tactics+URLs

Evaluates separately across all 7 mandatory subgroups:
1. Historical English
2. Modern Indian English
3. Romanized Hinglish
4. Native Devanagari Hindi
5. Obfuscated Messages (including controlled-pair label flip rate)
6. Hard Negatives (evaluating False Positive Rate)
7. Novel Threat Patterns

Integrates Phase 7 Semantic Analyzer for Step 8 Novelty Analysis.
Generates structured error analysis records for Step 10.
"""

from collections import defaultdict
import json
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple, Union

import numpy as np

from src.models.baseline_classifier import BaselineTextClassifier
from src.models.phase13.char_classifier import CharNgramClassifier
from src.models.phase13.hybrid_classifier import HybridFusionClassifier
from src.models.phase13.semantic_classifier import SemanticDenseClassifier
from src.semantic.analyzer import SemanticAnalyzer
from src.semantic.reference_index import SemanticReferenceIndex


def calc_metrics(tp: int, tn: int, fp: int, fn: int) -> Dict[str, Any]:
    """Computes standard classification metrics from confusion matrix counts."""
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


class Phase13Evaluator:
    """Evaluates Phase 13 experimental models against frozen baseline."""

    def __init__(self, base_dir: Optional[Union[str, Path]] = None):
        self.root_dir = Path(base_dir).resolve() if base_dir else Path(__file__).resolve().parents[3]
        self.data_dir = self.root_dir / "data" / "evaluation" / "phase13"
        self.models_dir = self.root_dir / "models" / "phase13"

        # 1. Load Model A (Frozen Baseline)
        baseline_dir = self.root_dir / "models" / "baseline"
        self.model_a = BaselineTextClassifier(model_dir=baseline_dir, threshold=0.30)

        # 2. Load Model B (Char n-gram)
        self.model_b = CharNgramClassifier(model_dir=self.models_dir / "char_ngram")

        # 3. Load Model C (Semantic Dense)
        self.model_c = SemanticDenseClassifier(model_dir=self.models_dir / "semantic_dense")

        # 4. Load Model D (Hybrid Fusion)
        self.model_d = HybridFusionClassifier(model_dir=self.models_dir / "hybrid_fusion")

        # 5. Load Semantic Analyzer for Step 8 Novelty Analysis
        ref_dir = self.root_dir / "data" / "semantic" / "reference"
        if ref_dir.is_dir() and (ref_dir / "reference_items.jsonl").is_file():
            try:
                ref_index = SemanticReferenceIndex.load(ref_dir)
                self.semantic_analyzer = SemanticAnalyzer(reference_index=ref_index)
            except Exception:
                self.semantic_analyzer = None
        else:
            self.semantic_analyzer = None

        # Load datasets
        self.datasets: Dict[str, List[Dict[str, Any]]] = {}
        self._load_datasets()

    def _load_jsonl(self, rel_path: str) -> List[Dict[str, Any]]:
        path = self.data_dir / rel_path
        if not path.is_file():
            return []
        with open(path, "r", encoding="utf-8") as f:
            return [json.loads(line) for line in f if line.strip()]

    def _load_datasets(self) -> None:
        self.datasets["train"] = self._load_jsonl("training/train.jsonl")
        self.datasets["val"] = self._load_jsonl("validation/val.jsonl")
        self.datasets["test"] = self._load_jsonl("test/test.jsonl")
        self.datasets["hard_negatives"] = self._load_jsonl("hard_negatives/hard_negatives.jsonl")
        self.datasets["multilingual"] = self._load_jsonl("multilingual/multilingual_cases.jsonl")
        self.datasets["obfuscation"] = self._load_jsonl("obfuscation/obfuscated_cases.jsonl")
        self.datasets["novel_patterns"] = self._load_jsonl("novel_patterns/novel_patterns.jsonl")

    def _predict_model(self, model_name: str, text: str) -> Tuple[str, float]:
        """Unified prediction runner returning (predicted_label, scam_probability)."""
        if model_name == "Model_A_Baseline":
            res = self.model_a.predict(text)
            return res["label"], float(res["probability"])
        elif model_name == "Model_B_CharNgram":
            prob = self.model_b.predict_proba(text)
            lbl = "scam" if prob >= self.model_b.threshold else "non_scam"
            return lbl, prob
        elif model_name == "Model_C_SemanticDense":
            prob = self.model_c.predict_proba(text)
            lbl = "scam" if prob >= self.model_c.threshold else "non_scam"
            return lbl, prob
        elif model_name == "Model_D_HybridFusion":
            prob, _ = self.model_d.predict_proba(text)
            lbl = "scam" if prob >= self.model_d.threshold else "non_scam"
            return lbl, prob
        else:
            raise ValueError(f"Unknown model name: {model_name}")

    def evaluate_subgroup(self, cases: List[Dict[str, Any]], model_name: str) -> Dict[str, Any]:
        """Evaluates a specific model on a collection of cases."""
        tp = tn = fp = fn = 0
        confidences = []
        for c in cases:
            text = c.get("text", "")
            gt = c.get("label")
            pred, prob = self._predict_model(model_name, text)
            confidences.append(prob)

            if gt == "scam":
                if pred == "scam":
                    tp += 1
                else:
                    fn += 1
            else:
                if pred == "scam":
                    fp += 1
                else:
                    tn += 1

        metrics = calc_metrics(tp, tn, fp, fn)
        metrics["mean_confidence"] = round(float(np.mean(confidences)), 4) if confidences else 0.0
        return metrics

    def run_controlled_comparison(self) -> Dict[str, Any]:
        """Executes full evaluation across all models and subgroups."""
        test_cases = self.datasets["test"]
        hard_neg_cases = self.datasets["hard_negatives"]
        ml_cases = self.datasets["multilingual"]
        obf_cases = self.datasets["obfuscation"]
        novel_cases = self.datasets["novel_patterns"]

        # Subgroup partitions
        subgroups: Dict[str, List[Dict[str, Any]]] = {
            "historical_english": [c for c in test_cases if "hist" in c.get("sample_id", "")],
            "modern_indian_english": [c for c in test_cases if "ind" in c.get("sample_id", "")],
            "romanized_hinglish": [c for c in ml_cases if c.get("language") == "hi-Latn"],
            "native_hindi": [c for c in ml_cases if c.get("language") == "hi"],
            "obfuscated_messages": obf_cases,
            "hard_negatives": hard_neg_cases,
            "novel_threat_patterns": novel_cases,
            "consolidated_test": test_cases,
        }

        models = [
            "Model_A_Baseline",
            "Model_B_CharNgram",
            "Model_C_SemanticDense",
            "Model_D_HybridFusion",
        ]

        comparison_results = {}
        for m in models:
            comparison_results[m] = {}
            for sg_name, cases in subgroups.items():
                comparison_results[m][sg_name] = self.evaluate_subgroup(cases, m)

        # Obfuscation controlled-pair analysis (label flip rate)
        controlled_pairs = self._evaluate_obfuscation_pairs()

        # Step 7 Tactic-aware ablation
        tactic_ablation = self._evaluate_tactic_ablation(test_cases)

        # Step 8 Novelty matrix analysis
        novelty_analysis = self._evaluate_novelty_matrix()

        # Step 10 Error analysis
        error_records = self._generate_error_analysis(test_cases + ml_cases + hard_neg_cases + novel_cases)

        full_results = {
            "comparison": comparison_results,
            "obfuscation_pairs": controlled_pairs,
            "tactic_ablation": tactic_ablation,
            "novelty_analysis": novelty_analysis,
            "error_analysis": error_records,
        }

        # Save to manifests
        manifest_path = self.data_dir / "manifests" / "evaluation_summary.json"
        manifest_path.parent.mkdir(parents=True, exist_ok=True)
        with open(manifest_path, "w", encoding="utf-8") as f:
            json.dump(full_results, f, indent=2)

        return full_results

    def _evaluate_obfuscation_pairs(self) -> Dict[str, Any]:
        """Calculates controlled-pair label flip rates for Model A vs Model B vs Model D."""
        obf_cases = self.datasets["obfuscation"]
        pairs_dict = defaultdict(dict)
        for c in obf_cases:
            grp = c["pattern_group_id"]
            if c["sample_id"].startswith("p13_obf_orig"):
                pairs_dict[grp]["orig"] = c
            else:
                pairs_dict[grp]["pert"] = c

        flips = {"Model_A_Baseline": 0, "Model_B_CharNgram": 0, "Model_D_HybridFusion": 0}
        total_pairs = len(pairs_dict)

        for grp, p in pairs_dict.items():
            orig_text = p["orig"]["text"]
            pert_text = p["pert"]["text"]

            for m in flips.keys():
                pred_orig, _ = self._predict_model(m, orig_text)
                pred_pert, _ = self._predict_model(m, pert_text)
                if pred_orig != pred_pert:
                    flips[m] += 1

        return {
            "total_pairs": total_pairs,
            "flips": flips,
            "flip_rates": {m: round(cnt / total_pairs, 4) for m, cnt in flips.items()},
        }

    def _evaluate_tactic_ablation(self, test_cases: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Compares Text Only vs Text + Tactics vs Text + Tactics + URLs on Model D."""
        # 1. Text Only (Model B)
        m_text = self.evaluate_subgroup(test_cases, "Model_B_CharNgram")

        # 2. Text + Tactics
        hybrid_tac = HybridFusionClassifier(
            model_dir=self.models_dir / "hybrid_fusion",
            include_tactics=True,
            include_urls=False,
            threshold=self.model_d.threshold,
        )
        tp = tn = fp = fn = 0
        for c in test_cases:
            p, _ = hybrid_tac.predict_proba(c["text"])
            pred = "scam" if p >= hybrid_tac.threshold else "non_scam"
            if c["label"] == "scam":
                if pred == "scam": tp += 1
                else: fn += 1
            else:
                if pred == "scam": fp += 1
                else: tn += 1
        m_tac = calc_metrics(tp, tn, fp, fn)

        # 3. Text + Tactics + URLs (Full Model D)
        m_full = self.evaluate_subgroup(test_cases, "Model_D_HybridFusion")

        return {
            "text_only": m_text,
            "text_plus_tactics": m_tac,
            "text_plus_tactics_plus_urls": m_full,
        }

    def _evaluate_novelty_matrix(self) -> Dict[str, Any]:
        """Categorizes cases across known/unknown and scam/non-scam using semantic reference."""
        if not self.semantic_analyzer:
            return {"status": "semantic_analyzer_unavailable"}

        all_eval_cases = (
            self.datasets["test"]
            + self.datasets["hard_negatives"]
            + self.datasets["multilingual"]
            + self.datasets["novel_patterns"]
        )

        matrix = {
            "known_scam": [],
            "known_non_scam": [],
            "unknown_scam": [],
            "unknown_non_scam": [],
        }

        for c in all_eval_cases:
            text = c["text"]
            gt = c["label"]
            status = c.get("known_unknown_status", "known_pattern")

            sem_res = self.semantic_analyzer.analyze(text, sample_id=c["sample_id"])
            max_sim = sem_res.semantic.top_1_similarity
            novelty = sem_res.semantic.semantic_novelty_score

            prob_b = self.model_b.predict_proba(text)

            entry = {
                "sample_id": c["sample_id"],
                "text": text[:60] + "...",
                "label": gt,
                "max_similarity": round(max_sim, 4),
                "novelty_score": round(novelty, 4),
                "model_b_prob": round(prob_b, 4),
            }

            if status == "known_pattern":
                if gt == "scam":
                    matrix["known_scam"].append(entry)
                else:
                    matrix["known_non_scam"].append(entry)
            else:
                if gt == "scam":
                    matrix["unknown_scam"].append(entry)
                else:
                    matrix["unknown_non_scam"].append(entry)

        summary = {k: {"count": len(v), "mean_novelty": round(float(np.mean([x["novelty_score"] for x in v])), 4) if v else 0.0,
                       "mean_similarity": round(float(np.mean([x["max_similarity"] for x in v])), 4) if v else 0.0}
                   for k, v in matrix.items()}

        return {"summary": summary, "matrix": matrix}

    def _generate_error_analysis(self, cases: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Compiles detailed error records for Model B failure modes."""
        errors = []
        for c in cases:
            text = c["text"]
            gt = c["label"]
            sample_id = c["sample_id"]
            lang = c.get("language", "en")
            script = c.get("script", "Latin")
            tactics = c.get("tactics", [])

            pred, prob = self._predict_model("Model_B_CharNgram", text)

            if pred != gt:
                failure_type = "false_positive" if pred == "scam" else "false_negative"

                likely_reason = "unspecified"
                if failure_type == "false_negative":
                    if lang == "hi":
                        likely_reason = "native_hindi_vocabulary_sparsity"
                    elif lang == "hi-Latn":
                        likely_reason = "code_mixed_phrasing_variation"
                    elif c.get("known_unknown_status") == "novel_pattern":
                        likely_reason = "novel_threat_vocabulary_divergence"
                    elif c.get("obfuscation_type") != "none":
                        likely_reason = "syntactic_obfuscation_evasion"
                    else:
                        likely_reason = "subtle_pretext_without_strong_lexical_cues"
                else:
                    # False positive
                    if "otp" in text.lower() or "verification" in text.lower():
                        likely_reason = "legitimate_security_alert_urgency"
                    elif "bill" in text.lower() or "power" in text.lower():
                        likely_reason = "legitimate_utility_notification_wording"
                    elif "refund" in text.lower():
                        likely_reason = "legitimate_transactional_refund_notice"
                    else:
                        likely_reason = "legitimate_urgent_banking_wording"

                # Semantic analysis if available
                sem_sim = 0.0
                novelty = 1.0
                if self.semantic_analyzer:
                    s_res = self.semantic_analyzer.analyze(text, sample_id=sample_id)
                    sem_sim = round(s_res.semantic.top_1_similarity, 4)
                    novelty = round(s_res.semantic.semantic_novelty_score, 4)

                errors.append({
                    "sample_id": sample_id,
                    "ground_truth": gt,
                    "prediction": pred,
                    "model_confidence": round(prob, 4),
                    "language": lang,
                    "script": script,
                    "tactics": tactics,
                    "semantic_similarity": sem_sim,
                    "novelty": novelty,
                    "failure_type": failure_type,
                    "likely_reason": likely_reason,
                    "text_snippet": text[:80] + "..." if len(text) > 80 else text,
                })

        return errors


if __name__ == "__main__":
    evaluator = Phase13Evaluator()
    results = evaluator.run_controlled_comparison()
    print("Controlled Comparison Execution Complete.")
    print("Models Evaluated:", list(results["comparison"].keys()))
