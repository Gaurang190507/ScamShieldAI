"""Command-Line Interface (CLI) for ScamShield AI investigations."""

import argparse
import json
from pathlib import Path
import sys

# Ensure project root is in sys.path
PROJECT_ROOT = Path(__file__).resolve().parents[2]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from src.app.schemas import InvestigationInput
from src.app.service import InvestigationService
from src.config.runtime_config import VERSION_METADATA


def build_parser() -> argparse.ArgumentParser:
    """Constructs CLI argument parser."""
    parser = argparse.ArgumentParser(
        description="ScamShield AI — Multi-Signal Forensic Investigation CLI",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--text", "-t", type=str, help="Suspicious message or communications text.")
    parser.add_argument("--url", "-u", type=str, help="Suspicious link or URL for passive analysis.")
    parser.add_argument("--image", "-i", type=str, help="Path to screenshot or image on disk.")
    parser.add_argument("--case-id", type=str, help="Optional custom case ID.")
    parser.add_argument(
        "--provider",
        choices=["mock", "groq", "gemini"],
        default="mock",
        help="Phase 10 LLM explanation provider (default: mock).",
    )
    parser.add_argument(
        "--top-k",
        type=int,
        default=3,
        help="Number of retrieved knowledge chunks (default: 3).",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Output raw JSON instead of formatted markdown.",
    )
    parser.add_argument(
        "--warmup",
        action="store_true",
        help="Pre-warm model caches before executing investigation.",
    )
    parser.add_argument(
        "--version",
        "-v",
        action="version",
        version=f"ScamShield AI {VERSION_METADATA.PROJECT_VERSION} ({VERSION_METADATA.PHASE_VERSION})",
    )
    return parser


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()

    if not args.text and not args.url and not args.image:
        parser.print_help()
        return 1

    try:
        service = InvestigationService(default_provider=args.provider)
        if args.warmup:
            service.warmup()

        inv_input = InvestigationInput(
            text=args.text,
            url=args.url,
            image_path=args.image,
            case_id=args.case_id,
            provider_name=args.provider,
            top_k=args.top_k,
        )

        report = service.investigate(inv_input)

        if args.json:
            print(json.dumps(report.to_dict(), indent=2))
        else:
            print(report.to_markdown())

        return 0

    except Exception as e:
        print(f"Error executing investigation: {e}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
