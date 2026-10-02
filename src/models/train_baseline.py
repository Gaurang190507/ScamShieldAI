"""Reproducible training and evaluation pipeline for ScamShield AI Phase 3 baseline."""

import json
import os
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, Any, Optional, Union, Tuple, List
import joblib
import numpy as np
import pandas as pd
import sklearn
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import (
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    confusion_matrix,
    roc_auc_score,
    classification_report,
)

from src.data.dataset_validator import DatasetValidator
from src.data.leakage_split import group_leakage_split, verify_no_group_leakage


def compute_binary_metrics(
    y_true: np.ndarray,
    y_prob: np.ndarray,
    threshold: float = 0.50,
) -> Dict[str, Any]:
    """Calculates comprehensive classification metrics for binary scam detection.

    Args:
        y_true: Ground truth binary array (1 = scam, 0 = non_scam).
        y_prob: Predicted probability array for class 1 (scam).
        threshold: Decision boundary threshold.

    Returns:
        Structured metrics dictionary.
    """
    y_pred = (y_prob >= threshold).astype(int)

    acc = float(accuracy_score(y_true, y_pred))
    p_scam = float(precision_score(y_true, y_pred, pos_label=1, zero_division=0))
    r_scam = float(recall_score(y_true, y_pred, pos_label=1, zero_division=0))
    f1_scam = float(f1_score(y_true, y_pred, pos_label=1, zero_division=0))

    p_non = float(precision_score(y_true, y_pred, pos_label=0, zero_division=0))
    r_non = float(recall_score(y_true, y_pred, pos_label=0, zero_division=0))
    f1_non = float(f1_score(y_true, y_pred, pos_label=0, zero_division=0))

    p_macro = float(precision_score(y_true, y_pred, average="macro", zero_division=0))
    r_macro = float(recall_score(y_true, y_pred, average="macro", zero_division=0))
    f1_macro = float(f1_score(y_true, y_pred, average="macro", zero_division=0))

    p_weighted = float(precision_score(y_true, y_pred, average="weighted", zero_division=0))
    r_weighted = float(recall_score(y_true, y_pred, average="weighted", zero_division=0))
    f1_weighted = float(f1_score(y_true, y_pred, average="weighted", zero_division=0))

    cm = confusion_matrix(y_true, y_pred).tolist()

    try:
        roc_auc = float(roc_auc_score(y_true, y_prob))
    except ValueError:
        roc_auc = 0.0

    return {
        "threshold": round(threshold, 4),
        "accuracy": round(acc, 4),
        "roc_auc": round(roc_auc, 4),
        "scam": {
            "precision": round(p_scam, 4),
            "recall": round(r_scam, 4),
            "f1_score": round(f1_scam, 4),
            "support": int((y_true == 1).sum()),
        },
        "non_scam": {
            "precision": round(p_non, 4),
            "recall": round(r_non, 4),
            "f1_score": round(f1_non, 4),
            "support": int((y_true == 0).sum()),
        },
        "macro_avg": {
            "precision": round(p_macro, 4),
            "recall": round(r_macro, 4),
            "f1_score": round(f1_macro, 4),
        },
        "weighted_avg": {
            "precision": round(p_weighted, 4),
            "recall": round(r_weighted, 4),
            "f1_score": round(f1_weighted, 4),
        },
        "confusion_matrix": {
            "tn": cm[0][0] if len(cm) > 0 else 0,
            "fp": cm[0][1] if len(cm) > 0 and len(cm[0]) > 1 else 0,
            "fn": cm[1][0] if len(cm) > 1 else 0,
            "tp": cm[1][1] if len(cm) > 1 and len(cm[1]) > 1 else 0,
            "matrix": cm,
        },
    }


def train_baseline(
    dataset_path: Optional[Union[str, Path]] = None,
    models_dir: Optional[Union[str, Path]] = None,
    eval_dir: Optional[Union[str, Path]] = None,
    random_state: int = 42,
) -> Dict[str, Any]:
    """Executes end-to-end reproducible baseline training and evaluation.

    Args:
        dataset_path: Path to preprocessed JSONL dataset.
        models_dir: Target directory for serialized model checkpoints.
        eval_dir: Target directory for evaluation metrics and error artifacts.
        random_state: Fixed random seed for split and model reproducibility.

    Returns:
        Comprehensive dictionary of training and evaluation results.
    """
    root_dir = Path(__file__).resolve().parents[2]
    if dataset_path is None:
        dataset_path = root_dir / "data" / "processed" / "preprocessed" / "uci_sms_spam.jsonl"
    if models_dir is None:
        models_dir = root_dir / "models" / "baseline"
    if eval_dir is None:
        eval_dir = root_dir / "data" / "evaluation" / "baseline"

    data_file = Path(dataset_path).resolve()
    model_path = Path(models_dir).resolve()
    eval_path = Path(eval_dir).resolve()

    model_path.mkdir(parents=True, exist_ok=True)
    eval_path.mkdir(parents=True, exist_ok=True)

    # 1. Load dataset
    if not data_file.is_file():
        raise FileNotFoundError(f"Dataset not found at: {data_file}")

    records: List[Dict[str, Any]] = []
    with open(data_file, "r", encoding="utf-8") as f:
        for line in f:
            line_str = line.strip()
            if line_str:
                records.append(json.loads(line_str))

    df = pd.DataFrame(records)

    # Validate dataset
    validator = DatasetValidator()
    val_res = validator.validate_dataset(records)
    if not val_res.is_valid:
        raise ValueError(f"Dataset failed canonical schema validation: {val_res.summary()}")

    # 2. Leakage-safe Group Splitting with Duplicate Text Clustering (70% train, 15% val, 15% test)
    # Threat campaigns broadcast superficial variations and identical messages.
    # To guarantee zero duplicate text leakage across partitions, we cluster samples
    # sharing normalized text together into the same partition, while concurrently
    # respecting any genuine multi-record pattern groups.
    parent = {idx: idx for idx in df.index}

    def find(i: int) -> int:
        if parent[i] != i:
            parent[i] = find(parent[i])
        return parent[i]

    def union(i: int, j: int) -> None:
        ri, rj = find(i), find(j)
        if ri != rj:
            parent[ri] = rj

    # A. Cluster samples sharing identical normalized_text (or exact text fallback)
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

    # Verify zero cluster leakage
    is_clean, leak_msg = verify_no_group_leakage(
        train_df, val_df, test_df, group_col="_split_cluster_id"
    )
    if not is_clean:
        raise RuntimeError(f"Data leakage detected during splitting: {leak_msg}")

    # Enforce zero duplicate text leakage across partitions
    train_norm = set(train_df["normalized_text"].astype(str).str.strip().str.lower())
    val_norm = set(val_df["normalized_text"].astype(str).str.strip().str.lower())
    test_norm = set(test_df["normalized_text"].astype(str).str.strip().str.lower())

    tv_leak = train_norm.intersection(val_norm)
    tt_leak = train_norm.intersection(test_norm)
    vt_leak = val_norm.intersection(test_norm)
    if tv_leak or tt_leak or vt_leak:
        raise RuntimeError(
            f"Duplicate text leakage detected! Overlaps: Train/Val={len(tv_leak)}, "
            f"Train/Test={len(tt_leak)}, Val/Test={len(vt_leak)}"
        )

    # Text inputs and targets
    X_train_text = train_df["text"].astype(str)
    X_val_text = val_df["text"].astype(str)
    X_test_text = test_df["text"].astype(str)

    y_train = (train_df["label"] == "scam").astype(int).values
    y_val = (val_df["label"] == "scam").astype(int).values
    y_test = (test_df["label"] == "scam").astype(int).values

    # 3. Fit TF-IDF on Training Data ONLY
    tfidf_config = {
        "ngram_range": (1, 2),
        "min_df": 2,
        "max_df": 0.9,
        "sublinear_tf": True,
        "strip_accents": "unicode",
    }
    vectorizer = TfidfVectorizer(**tfidf_config)
    X_train_vec = vectorizer.fit_transform(X_train_text)
    X_val_vec = vectorizer.transform(X_val_text)
    X_test_vec = vectorizer.transform(X_test_text)

    vocab_size = len(vectorizer.vocabulary_)

    # 4. Train Logistic Regression
    lr_config = {
        "C": 1.0,
        "solver": "lbfgs",
        "max_iter": 1000,
        "random_state": random_state,
    }
    classifier = LogisticRegression(**lr_config)
    classifier.fit(X_train_vec, y_train)

    # 5. Validation Evaluation & Threshold Analysis
    val_probs = classifier.predict_proba(X_val_vec)[:, 1]
    candidate_thresholds = [0.30, 0.40, 0.50, 0.60, 0.70]
    threshold_evaluations = {}
    best_threshold = 0.50
    best_val_f1 = -1.0

    for t in candidate_thresholds:
        t_metrics = compute_binary_metrics(y_val, val_probs, threshold=t)
        threshold_evaluations[str(t)] = t_metrics
        if t_metrics["scam"]["f1_score"] > best_val_f1:
            best_val_f1 = t_metrics["scam"]["f1_score"]
            best_threshold = t

    # 6. Test Set Final Evaluation
    test_probs = classifier.predict_proba(X_test_vec)[:, 1]
    test_metrics_default = compute_binary_metrics(y_test, test_probs, threshold=0.50)
    test_metrics_selected = compute_binary_metrics(y_test, test_probs, threshold=best_threshold)

    # 7. Generate Test Predictions & Error Analysis Artifacts
    test_preds_selected = (test_probs >= best_threshold).astype(int)
    predictions_records: List[Dict[str, Any]] = []
    error_records: List[Dict[str, Any]] = []

    for i, (_, row) in enumerate(test_df.iterrows()):
        prob = float(test_probs[i])
        pred_label = "scam" if prob >= best_threshold else "non_scam"
        true_label = row["label"]
        pred_rec = {
            "sample_id": row["sample_id"],
            "text": row["text"],
            "true_label": true_label,
            "predicted_label": pred_label,
            "predicted_probability": round(prob, 4),
            "threshold": round(best_threshold, 4),
            "source_reference": row.get("source_reference", ""),
        }
        predictions_records.append(pred_rec)

        # Check for errors
        if pred_label != true_label:
            err_type = "false_positive" if (true_label == "non_scam" and pred_label == "scam") else "false_negative"
            dist = round(abs(prob - best_threshold), 4)
            err_entry = dict(pred_rec)
            err_entry["error_type"] = err_type
            err_entry["distance_from_threshold"] = dist
            error_records.append(err_entry)

    # Split Statistics
    split_stats = {
        "total_samples": len(df),
        "overall_distribution": {
            "scam": int((df["label"] == "scam").sum()),
            "non_scam": int((df["label"] == "non_scam").sum()),
            "scam_percentage": round(float((df["label"] == "scam").mean()) * 100, 2),
            "non_scam_percentage": round(float((df["label"] == "non_scam").mean()) * 100, 2),
        },
        "train": {
            "count": len(train_df),
            "percentage": round(len(train_df) / len(df) * 100, 2),
            "scam_count": int((train_df["label"] == "scam").sum()),
            "non_scam_count": int((train_df["label"] == "non_scam").sum()),
            "scam_percentage": round(float((train_df["label"] == "scam").mean()) * 100, 2),
        },
        "validation": {
            "count": len(val_df),
            "percentage": round(len(val_df) / len(df) * 100, 2),
            "scam_count": int((val_df["label"] == "scam").sum()),
            "non_scam_count": int((val_df["label"] == "non_scam").sum()),
            "scam_percentage": round(float((val_df["label"] == "scam").mean()) * 100, 2),
        },
        "test": {
            "count": len(test_df),
            "percentage": round(len(test_df) / len(df) * 100, 2),
            "scam_count": int((test_df["label"] == "scam").sum()),
            "non_scam_count": int((test_df["label"] == "non_scam").sum()),
            "scam_percentage": round(float((test_df["label"] == "scam").mean()) * 100, 2),
        },
        "leakage_verification": leak_msg,
        "duplicate_text_leakage": "0 (verified zero exact or normalized duplicate text overlap across splits)",
        "unique_split_clusters": int(df["_split_cluster_id"].nunique()),
    }

    # Model metadata
    metadata = {
        "model_name": "ScamShield Phase 3 baseline text classifier",
        "description": "Text-only TF-IDF + Logistic Regression baseline trained on UCI SMS Spam Collection",
        "timestamp_utc": datetime.now(timezone.utc).isoformat(),
        "random_state": random_state,
        "dataset_source": str(data_file),
        "dataset_samples": len(df),
        "split_counts": {
            "train": len(train_df),
            "validation": len(val_df),
            "test": len(test_df),
        },
        "tfidf_hyperparameters": tfidf_config,
        "vocabulary_size": vocab_size,
        "logistic_regression_hyperparameters": lr_config,
        "selected_threshold": best_threshold,
        "default_threshold": 0.50,
        "threshold_selection_criterion": "highest scam F1-score on validation set",
        "library_versions": {
            "sklearn": getattr(sklearn, "__version__", "unknown"),
            "joblib": getattr(joblib, "__version__", "unknown"),
        },
    }

    # 8. Save Model Artifacts
    joblib.dump(vectorizer, model_path / "tfidf_vectorizer.joblib")
    joblib.dump(classifier, model_path / "logistic_regression.joblib")
    with open(model_path / "model_metadata.json", "w", encoding="utf-8") as f:
        json.dump(metadata, f, indent=2)

    # 9. Save Evaluation Artifacts
    combined_metrics = {
        "metadata": metadata,
        "validation_threshold_tuning": threshold_evaluations,
        "validation_selected": threshold_evaluations[str(best_threshold)],
        "test_selected_threshold": test_metrics_selected,
        "test_default_threshold": test_metrics_default,
    }

    with open(eval_path / "metrics.json", "w", encoding="utf-8") as f:
        json.dump(combined_metrics, f, indent=2)

    with open(eval_path / "confusion_matrix.json", "w", encoding="utf-8") as f:
        json.dump(
            {
                "selected_threshold_0.30": test_metrics_selected["confusion_matrix"],
                "default_threshold_0.50": test_metrics_default["confusion_matrix"],
            },
            f,
            indent=2,
        )

    with open(eval_path / "split_statistics.json", "w", encoding="utf-8") as f:
        json.dump(split_stats, f, indent=2)

    with open(eval_path / "model_config.json", "w", encoding="utf-8") as f:
        json.dump(
            {
                "tfidf": tfidf_config,
                "logistic_regression": lr_config,
                "selected_threshold": best_threshold,
                "vocabulary_size": vocab_size,
            },
            f,
            indent=2,
        )

    # Save test predictions JSONL
    with open(eval_path / "test_predictions.jsonl", "w", encoding="utf-8") as f:
        for pr in predictions_records:
            f.write(json.dumps(pr, ensure_ascii=False) + "\n")

    # Save error analysis JSONL
    with open(eval_path / "error_analysis.jsonl", "w", encoding="utf-8") as f:
        for er in error_records:
            f.write(json.dumps(er, ensure_ascii=False) + "\n")

    # Generate human-readable README in evaluation directory
    generate_eval_readme(
        eval_path / "README.md",
        split_stats=split_stats,
        test_metrics_selected=test_metrics_selected,
        test_metrics_default=test_metrics_default,
        error_records=error_records,
        best_threshold=best_threshold,
    )

    return {
        "split_statistics": split_stats,
        "vocabulary_size": vocab_size,
        "selected_threshold": best_threshold,
        "validation_metrics": threshold_evaluations[str(best_threshold)],
        "test_metrics_selected": test_metrics_selected,
        "test_metrics_default": test_metrics_default,
        "error_count": len(error_records),
        "models_dir": str(model_path),
        "eval_dir": str(eval_path),
    }


def generate_eval_readme(
    report_path: Path,
    split_stats: Dict[str, Any],
    test_metrics_selected: Dict[str, Any],
    test_metrics_default: Dict[str, Any],
    error_records: List[Dict[str, Any]],
    best_threshold: float,
) -> None:
    """Generates an auditable markdown evaluation summary report."""
    fp_count = sum(1 for e in error_records if e["error_type"] == "false_positive")
    fn_count = sum(1 for e in error_records if e["error_type"] == "false_negative")

    md = f"""# ScamShield AI — Phase 3 Baseline Evaluation Report

**Model:** Text-only TF-IDF + Logistic Regression  
**Dataset:** UCI SMS Spam Collection (`data/processed/preprocessed/uci_sms_spam.jsonl`)  
**Evaluation Mode:** Leakage-safe Group Partitioning with Duplicate Text Clustering (70% Train / 15% Val / 15% Test)  

---

## 1. Dataset Partitioning & Leakage Safeguards

All campaign clusters and normalized duplicate text clusters were partitioned with zero pattern group overlap and zero duplicate text overlap:

| Split | Count | Proportion | Scam Samples | Non-Scam Samples | Scam % |
| :--- | :---: | :---: | :---: | :---: | :---: |
| **Train** | {split_stats['train']['count']} | {split_stats['train']['percentage']}% | {split_stats['train']['scam_count']} | {split_stats['train']['non_scam_count']} | {split_stats['train']['scam_percentage']}% |
| **Validation** | {split_stats['validation']['count']} | {split_stats['validation']['percentage']}% | {split_stats['validation']['scam_count']} | {split_stats['validation']['non_scam_count']} | {split_stats['validation']['scam_percentage']}% |
| **Test** | {split_stats['test']['count']} | {split_stats['test']['percentage']}% | {split_stats['test']['scam_count']} | {split_stats['test']['non_scam_count']} | {split_stats['test']['scam_percentage']}% |
| **Total** | **{split_stats['total_samples']}** | **100.0%** | **{split_stats['overall_distribution']['scam']}** | **{split_stats['overall_distribution']['non_scam']}** | **{split_stats['overall_distribution']['scam_percentage']}%** |

*Leakage Verification:* {split_stats['leakage_verification']}  
*Duplicate Text Isolation:* {split_stats.get('duplicate_text_leakage', 'Zero duplicate leakage')}  
*Unique Split Clusters:* {split_stats.get('unique_split_clusters', 'N/A')} clusters across 5,574 samples.

---

## 2. Test Set Performance

### Selected Operating Threshold ({best_threshold:.2f} — Tuned on Validation F1)
- **Accuracy**: `{test_metrics_selected['accuracy'] * 100:.2f}%`
- **ROC-AUC**: `{test_metrics_selected['roc_auc']:.4f}`
- **Scam Precision**: `{test_metrics_selected['scam']['precision'] * 100:.2f}%`
- **Scam Recall**: `{test_metrics_selected['scam']['recall'] * 100:.2f}%`
- **Scam F1-Score**: `{test_metrics_selected['scam']['f1_score'] * 100:.2f}%`
- **Macro Avg F1**: `{test_metrics_selected['macro_avg']['f1_score'] * 100:.2f}%`
- **Weighted Avg F1**: `{test_metrics_selected['weighted_avg']['f1_score'] * 100:.2f}%`

**Confusion Matrix (Threshold {best_threshold:.2f}):**
- True Negatives (TN): `{test_metrics_selected['confusion_matrix']['tn']}`
- False Positives (FP): `{test_metrics_selected['confusion_matrix']['fp']}`
- False Negatives (FN): `{test_metrics_selected['confusion_matrix']['fn']}`
- True Positives (TP): `{test_metrics_selected['confusion_matrix']['tp']}`

### Default Threshold (0.50 Reference)
- **Accuracy**: `{test_metrics_default['accuracy'] * 100:.2f}%`
- **ROC-AUC**: `{test_metrics_default['roc_auc']:.4f}`
- **Scam Precision**: `{test_metrics_default['scam']['precision'] * 100:.2f}%`
- **Scam Recall**: `{test_metrics_default['scam']['recall'] * 100:.2f}%`
- **Scam F1-Score**: `{test_metrics_default['scam']['f1_score'] * 100:.2f}%`

*Threshold Analysis Note:* At 0.50, the model achieves {test_metrics_default['scam']['precision'] * 100:.2f}% precision but suffers lower recall ({test_metrics_default['scam']['recall'] * 100:.2f}%), missing {test_metrics_default['confusion_matrix']['fn']} spam/scam messages due to dataset class imbalance ({split_stats['overall_distribution']['non_scam_percentage']}% non-scam vs {split_stats['overall_distribution']['scam_percentage']}% scam). Lowering the decision threshold to {best_threshold:.2f} on the validation set reduces false negatives to {test_metrics_selected['confusion_matrix']['fn']} while maintaining {test_metrics_selected['scam']['precision'] * 100:.2f}% precision.

---

## 3. Error Analysis Summary

Total Test Errors at Threshold {best_threshold:.2f}: **{len(error_records)}** / {split_stats['test']['count']} samples ({len(error_records)/split_stats['test']['count']*100:.2f}% error rate).

### False Positives (Actual: Non-Scam → Predicted: Scam) [{fp_count} Cases]
Legitimate messages containing commercial or call cues that triggered high spam token weights:
"""
    for e in [x for x in error_records if x["error_type"] == "false_positive"][:5]:
        md += f"- **[{e['sample_id']}]** (prob: `{e['predicted_probability']:.4f}`): \"{e['text']}\"\n"

    md += f"""
### False Negatives (Actual: Scam → Predicted: Non-Scam) [{fn_count} Cases]
Spam messages that evaded word-level TF-IDF features due to conversational phrasing, news reporting format, or typos:
"""
    for e in [x for x in error_records if x["error_type"] == "false_negative"][:7]:
        md += f"- **[{e['sample_id']}]** (prob: `{e['predicted_probability']:.4f}`): \"{e['text']}\"\n"

    md += """
---

## 4. Key Takeaways & Limitations

1. **Text-Only Baseline**: Relies purely on lexical TF-IDF n-grams without multi-label tactical indicators, URL structural heuristics, or semantic representations.
2. **Historical Dataset**: The UCI SMS Spam Collection reflects 2011 UK/Singapore carrier SMS spam. It lacks modern Indian vectors (digital arrest, APK sideloading, UPI fraud).
3. **Spam vs. Scam**: Many historical spam samples are commercial ringtone or adult chat advertisements rather than fraudulent identity theft attacks.
"""

    with open(report_path, "w", encoding="utf-8") as f:
        f.write(md)


if __name__ == "__main__":
    print("=" * 60)
    print("   ScamShield AI — Phase 3 ML Baseline Training")
    print("=" * 60)
    results = train_baseline()
    print("Training and evaluation successfully completed!")
    print(f"Vocabulary Size:          {results['vocabulary_size']}")
    print(f"Selected Threshold:       {results['selected_threshold']}")
    print(f"Test Accuracy (0.30):     {results['test_metrics_selected']['accuracy'] * 100:.2f}%")
    print(f"Test Scam Precision:      {results['test_metrics_selected']['scam']['precision'] * 100:.2f}%")
    print(f"Test Scam Recall:         {results['test_metrics_selected']['scam']['recall'] * 100:.2f}%")
    print(f"Test Scam F1:             {results['test_metrics_selected']['scam']['f1_score'] * 100:.2f}%")
    print(f"Test ROC-AUC:             {results['test_metrics_selected']['roc_auc']:.4f}")
    print(f"Total Test Errors:        {results['error_count']}")
    print(f"Artifacts Saved To:       {results['models_dir']}")
    print(f"Evaluation Saved To:      {results['eval_dir']}")
    print("=" * 60)
