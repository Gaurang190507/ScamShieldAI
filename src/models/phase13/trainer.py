"""Training and threshold calibration orchestrator for ScamShield AI Phase 13.

Coordinates:
1. Training Model B (Character n-gram TF-IDF + Logistic Regression).
2. Training Model C (Offline Dense Semantic Embeddings + Logistic Regression).
3. Training Model D (Tactic-Aware + URL Multimodal Hybrid Fusion).
4. Rigorous threshold calibration on the Phase 13 validation set (NOT the test set).
5. Serialization of trained artifacts into models/phase13/.
"""

import json
from pathlib import Path
from typing import Any, Dict, List, Tuple

import numpy as np

from .char_classifier import CharNgramClassifier
from .hybrid_classifier import HybridFusionClassifier
from .semantic_classifier import SemanticDenseClassifier


def calc_metrics(y_true: List[int], probs: List[float], threshold: float) -> Dict[str, float]:
    """Calculates precision, recall, F1, FPR, FNR for a given probability threshold."""
    y_pred = [1 if p >= threshold else 0 for p in probs]
    tp = sum(1 for yt, yp in zip(y_true, y_pred) if yt == 1 and yp == 1)
    tn = sum(1 for yt, yp in zip(y_true, y_pred) if yt == 0 and yp == 0)
    fp = sum(1 for yt, yp in zip(y_true, y_pred) if yt == 0 and yp == 1)
    fn = sum(1 for yt, yp in zip(y_true, y_pred) if yt == 1 and yp == 0)

    total = tp + tn + fp + fn
    accuracy = round((tp + tn) / total, 4) if total > 0 else 0.0
    precision = round(tp / (tp + fp), 4) if (tp + fp) > 0 else 0.0
    recall = round(tp / (tp + fn), 4) if (tp + fn) > 0 else 0.0
    f1 = round(2 * precision * recall / (precision + recall), 4) if (precision + recall) > 0 else 0.0
    fpr = round(fp / (fp + tn), 4) if (fp + tn) > 0 else 0.0
    fnr = round(fn / (fn + tp), 4) if (fn + tp) > 0 else 0.0

    return {
        "threshold": round(threshold, 4),
        "tp": tp,
        "tn": tn,
        "fp": fp,
        "fn": fn,
        "accuracy": accuracy,
        "precision": precision,
        "recall": recall,
        "f1": f1,
        "fpr": fpr,
        "fnr": fnr,
    }


class Phase13Trainer:
    """Manages training and validation calibration for Phase 13 experimental models."""

    def __init__(self, base_dir: Path):
        self.base_dir = base_dir
        self.data_dir = base_dir / "data" / "evaluation" / "phase13"
        self.models_dir = base_dir / "models" / "phase13"

    def _load_jsonl(self, path: Path) -> List[Dict[str, Any]]:
        with open(path, "r", encoding="utf-8") as f:
            return [json.loads(line) for line in f if line.strip()]

    def run(self) -> Dict[str, Any]:
        """Executes full training pipeline and calibration."""
        train_cases = self._load_jsonl(self.data_dir / "training" / "train.jsonl")
        val_cases = self._load_jsonl(self.data_dir / "validation" / "val.jsonl")

        train_texts = [c["text"] for c in train_cases]
        train_labels = [1 if c["label"] == "scam" else 0 for c in train_cases]

        val_texts = [c["text"] for c in val_cases]
        val_labels = [1 if c["label"] == "scam" else 0 for c in val_cases]

        # 1. Train Model B (Char n-gram)
        print("Training Model B (Char n-gram TF-IDF)...")
        model_b = CharNgramClassifier(threshold=0.35)
        model_b.fit(train_texts, train_labels)

        # 2. Train Model C (Semantic Dense)
        print("Training Model C (Offline Semantic Dense)...")
        model_c = SemanticDenseClassifier(threshold=0.40)
        model_c.fit(train_texts, train_labels)

        # 3. Train Model D (Hybrid Fusion)
        print("Training Model D (Tactic + URL Hybrid Fusion)...")
        model_d = HybridFusionClassifier(threshold=0.35)
        model_d.fit(train_texts, train_labels)

        # 4. Calibrate thresholds on Validation set
        candidate_thresholds = [0.20, 0.25, 0.30, 0.35, 0.40, 0.45, 0.50, 0.55, 0.60]
        val_probs_b = [model_b.predict_proba(t) for t in val_texts]
        val_probs_c = [model_c.predict_proba(t) for t in val_texts]
        val_probs_d = [model_d.predict_proba(t)[0] for t in val_texts]

        calibrations = {"Model_B": [], "Model_C": [], "Model_D": []}

        best_thresh_b = 0.35
        best_f1_b = -1.0
        for th in candidate_thresholds:
            m = calc_metrics(val_labels, val_probs_b, th)
            calibrations["Model_B"].append(m)
            if m["f1"] > best_f1_b and m["fpr"] <= 0.15:
                best_f1_b = m["f1"]
                best_thresh_b = th

        best_thresh_c = 0.40
        best_f1_c = -1.0
        for th in candidate_thresholds:
            m = calc_metrics(val_labels, val_probs_c, th)
            calibrations["Model_C"].append(m)
            if m["f1"] > best_f1_c and m["fpr"] <= 0.15:
                best_f1_c = m["f1"]
                best_thresh_c = th

        best_thresh_d = 0.35
        best_f1_d = -1.0
        for th in candidate_thresholds:
            m = calc_metrics(val_labels, val_probs_d, th)
            calibrations["Model_D"].append(m)
            if m["f1"] > best_f1_d and m["fpr"] <= 0.15:
                best_f1_d = m["f1"]
                best_thresh_d = th

        # Update operating thresholds
        model_b.threshold = best_thresh_b
        model_c.threshold = best_thresh_c
        model_d.threshold = best_thresh_d

        # 5. Serialize models
        model_b.save(self.models_dir / "char_ngram")
        model_c.save(self.models_dir / "semantic_dense")
        model_d.save(self.models_dir / "hybrid_fusion")

        # 6. Save calibration manifest
        calib_out = self.data_dir / "manifests" / "threshold_calibration.json"
        calib_out.parent.mkdir(parents=True, exist_ok=True)
        summary = {
            "selected_thresholds": {
                "Model_B": best_thresh_b,
                "Model_C": best_thresh_c,
                "Model_D": best_thresh_d,
            },
            "validation_grid": calibrations,
        }
        with open(calib_out, "w", encoding="utf-8") as f:
            json.dump(summary, f, indent=2)

        print("Phase 13 Models Trained & Calibrated:")
        print(f"  - Model B selected threshold: {best_thresh_b} (Val F1: {best_f1_b:.4f})")
        print(f"  - Model C selected threshold: {best_thresh_c} (Val F1: {best_f1_c:.4f})")
        print(f"  - Model D selected threshold: {best_thresh_d} (Val F1: {best_f1_d:.4f})")

        return summary


if __name__ == "__main__":
    trainer = Phase13Trainer(base_dir=Path(__file__).resolve().parents[3])
    trainer.run()
