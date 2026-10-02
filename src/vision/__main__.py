"""CLI entry point for ScamShield AI Phase 9B Visual Scam Classification.

Usage:
    python -m src.vision --demo
    python -m src.vision --image path/to/screenshot.png
    python -m src.vision --evaluate
    python -m src.vision --build-dataset
"""

import argparse
import json
from pathlib import Path
import sys

from .dataset_generator import build_synthetic_dataset
from .evaluate_visual import run_phase9b_experiments
from .leakage import partition_by_group
from .schemas import VisualSampleRecord
from .visual_classifier import VisualScamClassifier
from .visual_predictor import VisualPredictor


def main() -> None:
    parser = argparse.ArgumentParser(
        description="ScamShield AI Phase 9B — Visual Scam Classification & Forensic Evidence"
    )
    parser.add_argument(
        "--demo",
        action="store_true",
        help="Run comprehensive demo across representative samples (Scam, Hard Negative, Benign)",
    )
    parser.add_argument(
        "--image",
        type=str,
        help="Path to an image to evaluate with the visual predictor",
    )
    parser.add_argument(
        "--evaluate",
        action="store_true",
        help="Run controlled evaluation experiments (Exp A: Text, Exp B: Visual, Exp C: Fusion)",
    )
    parser.add_argument(
        "--build-dataset",
        action="store_true",
        help="Generate synthetic visual benchmark corpus and manifest",
    )

    args = parser.parse_args()

    if args.build_dataset:
        print("[*] Generating Phase 9B synthetic visual dataset...")
        recs, manifest_p = build_synthetic_dataset(Path("data/visual"))
        print(f"[+] Successfully generated {len(recs)} records at: {manifest_p}")
        return

    if args.evaluate:
        print("[*] Running Phase 9B controlled evaluation experiments...")
        summary = run_phase9b_experiments()
        print("\n=== PHASE 9B EXPERIMENT RESULTS ===")
        for exp_name, metrics in summary["experiments"].items():
            print(f"\n{exp_name.upper()}:")
            for k, v in metrics.items():
                print(f"  {k}: {v}")
        hn = summary["hard_negative_analysis"]
        print(f"\nHARD NEGATIVE FALSE POSITIVES:")
        print(f"  Visual Only: {hn['visual_false_positives']} / {hn['total_hard_negatives']} ({hn['visual_false_positive_rate']*100:.1f}%)")
        print(f"  Text Only:   {hn['text_false_positives']} / {hn['total_hard_negatives']} ({hn['text_false_positive_rate']*100:.1f}%)")
        print(f"  Fusion:      {hn['fusion_false_positives']} / {hn['total_hard_negatives']} ({hn['fusion_false_positive_rate']*100:.1f}%)")
        return

    if args.image:
        img_p = Path(args.image)
        if not img_p.is_file():
            print(f"Error: Image file not found at '{img_p}'", file=sys.stderr)
            sys.exit(1)

        manifest_p = Path("data/visual/metadata/dataset_manifest.json")
        if not manifest_p.is_file():
            print("[*] Dataset manifest not found. Building dataset first...")
            build_synthetic_dataset(Path("data/visual"))

        manifest = json.loads(manifest_p.read_text(encoding="utf-8"))
        recs = [VisualSampleRecord(**r) for r in manifest["records"]]
        train_recs, val_recs, _ = partition_by_group(recs)

        clf = VisualScamClassifier()
        clf.fit(train_recs)
        clf.tune_threshold(val_recs)

        predictor = VisualPredictor(clf)
        result = predictor.predict_image(img_p)

        print(f"\n--- Visual Classification Result for: {img_p.name} ---")
        print(f"Predicted Label:   {result.predicted_label.upper()}")
        print(f"Scam Probability:  {result.probability:.4f} (Threshold: {result.threshold:.4f})")
        print(f"Dimensions:        {result.features['width']}x{result.features['height']}")
        print(f"Red Ratio:         {result.features['red_ratio']:.4f}")
        print(f"Edge Density:      {result.features['edge_density']:.4f}")
        print(f"Header Detected:   {result.features['header_banner_detected']}")
        print(f"Buttons Detected:  {result.features['button_candidate_count']}")
        print(f"QR Detected:       {result.features['qr_candidate_detected']}")

        print(f"\nExtracted Visual Evidence ({len(result.evidence)} items):")
        for ev in result.evidence:
            print(f"  [{ev.feature}] = {ev.value}: {ev.reason}")
        return

    # Default: Demo mode
    print("=== ScamShield AI Phase 9B — Visual Classification Demo ===\n")
    manifest_p = Path("data/visual/metadata/dataset_manifest.json")
    if not manifest_p.is_file():
        print("[*] Building synthetic visual dataset...")
        build_synthetic_dataset(Path("data/visual"))

    manifest = json.loads(manifest_p.read_text(encoding="utf-8"))
    recs = [VisualSampleRecord(**r) for r in manifest["records"]]
    train_recs, val_recs, _ = partition_by_group(recs)

    clf = VisualScamClassifier()
    clf.fit(train_recs)
    clf.tune_threshold(val_recs)
    predictor = VisualPredictor(clf)

    demo_ids = ["legit_delivery_01", "scam_acct_lock_01", "hard_neg_qr_01"]
    for d_id in demo_ids:
        rec = next((r for r in recs if r.image_id == d_id), None)
        if not rec:
            continue
        res = predictor.predict_image(rec.image_path, image_id=rec.image_id)
        print(f"Sample: {rec.image_id} (Ground Truth: {rec.label})")
        print(f"  Scenario:          {rec.scenario}")
        print(f"  Visual Prediction: {res.predicted_label.upper()} (Prob: {res.probability:.4f}, Thresh: {res.threshold:.4f})")
        print(f"  Evidence Items:    {len(res.evidence)}")
        for e in res.evidence:
            print(f"    - {e.feature}: {e.reason}")
        print()


if __name__ == "__main__":
    main()
