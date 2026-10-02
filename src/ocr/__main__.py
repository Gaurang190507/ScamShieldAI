"""CLI runner and demo tool for ScamShield AI Phase 9A OCR Ingestion & Assessment.

Usage:
    python -m src.ocr --demo
    python -m src.ocr --image tests/fixtures/images/fixture_01_scam.png
    python -m src.ocr --image tests/fixtures/images/fixture_01_scam.png --json
"""

import argparse
import json
from pathlib import Path
import sys

from .extractor import ImageCaseAssessmentPipeline


def run_demo() -> None:
    """Runs demonstration of OCR ingestion and downstream ScamShield evaluation on fixtures."""
    if hasattr(sys.stdout, "reconfigure"):
        try:
            sys.stdout.reconfigure(encoding="utf-8")
        except Exception:
            pass
    fixtures_dir = Path(__file__).resolve().parents[2] / "tests" / "fixtures" / "images"
    manifest_path = fixtures_dir / "manifest.json"

    if not manifest_path.is_file():
        print(f"Error: Fixtures manifest not found at {manifest_path}")
        print("Run `python -m tests.fixtures.create_fixtures` first.")
        sys.exit(1)

    with open(manifest_path, "r", encoding="utf-8") as f:
        manifest = json.load(f)

    print("=" * 80)
    print("ScamShield AI — Phase 9A: Screenshot Ingestion & Multi-Signal OCR Assessment")
    print("=" * 80)
    print(f"Loaded {len(manifest)} synthetic test fixtures from {fixtures_dir}")
    print("Initializing ImageCaseAssessmentPipeline (offline, deterministic)...\n")

    pipeline = ImageCaseAssessmentPipeline(enable_semantic=True)

    for fname, meta in manifest.items():
        img_path = fixtures_dir / fname
        print("-" * 80)
        print(f"FIXTURE: {fname} ({meta.get('description')})")
        print(f"Dimensions: {meta.get('width')}x{meta.get('height')} | Ground Truth Label: {meta.get('label')}")
        print("-" * 80)

        result = pipeline.analyze_image(image_path=img_path)

        print(f"OCR Status:          {result.ocr.status}")
        print(f"OCR Engine:          {result.ocr.engine}")
        print(f"Raw Text Extracted:  {repr(result.ocr.raw_text[:60]) + '...' if len(result.ocr.raw_text) > 60 else repr(result.ocr.raw_text)}")
        print(f"Extracted Entities:")
        print(f"  - URLs:     {result.entities.urls}")
        print(f"  - Phones:   {result.entities.phone_numbers}")
        print(f"  - Emails:   {result.entities.email_addresses}")
        print(f"  - Currency: {result.entities.currency_mentions}")
        print(f"  - OTP:      {result.entities.otp_mentions}")

        if result.assessment:
            ass = result.assessment.get("assessment", {})
            audit = result.assessment.get("audit", {})
            print(f"\nDownstream ScamShield Assessment:")
            print(f"  Status:             {ass.get('status', '').upper()}")
            print(f"  Evidence Level:     {ass.get('evidence_level', '').upper()}")
            print(f"  Signal Consistency: {ass.get('signal_consistency', '')}")
            print(f"  Decision Rule:      {audit.get('final_decision_rule', '')}")
        else:
            print(f"\nDownstream ScamShield Assessment: Skipped ({result.ocr.status})")

        print(f"Audit Trail:")
        print(f"  Network Access:                 {result.audit.network_access}")
        print(f"  External Service:               {result.audit.external_service}")
        print(f"  Spatial Coordinates Available:  {result.audit.spatial_coordinates_available}")

        if result.warnings:
            print("Warnings:")
            for w in result.warnings:
                print(f"  ! {w}")

        print("\n")


def main() -> None:
    """CLI entry point."""
    if hasattr(sys.stdout, "reconfigure"):
        try:
            sys.stdout.reconfigure(encoding="utf-8")
        except Exception:
            pass

    parser = argparse.ArgumentParser(
        description="ScamShield AI Phase 9A OCR Ingestion & Analysis"
    )
    parser.add_argument(
        "--demo", action="store_true", help="Run predefined demo across test image fixtures."
    )
    parser.add_argument(
        "--image", type=str, default=None, help="Path to input image file."
    )
    parser.add_argument(
        "--json", action="store_true", help="Output result as JSON."
    )

    args = parser.parse_args()

    if args.demo:
        run_demo()
    elif args.image:
        pipeline = ImageCaseAssessmentPipeline(enable_semantic=True)
        result = pipeline.analyze_image(image_path=args.image)
        if args.json:
            print(json.dumps(result.to_dict(), indent=2))
        else:
            print(f"Image:          {result.input.filename} ({result.input.width}x{result.input.height})")
            print(f"OCR Status:     {result.ocr.status}")
            print(f"Engine:         {result.ocr.engine}")
            print(f"Raw Text:       {repr(result.ocr.raw_text)}")
            if result.assessment:
                ass = result.assessment.get("assessment", {})
                print(f"Status:         {ass.get('status')}")
                print(f"Evidence Level: {ass.get('evidence_level')}")
                print(f"Rule:           {result.assessment.get('audit', {}).get('final_decision_rule')}")
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
