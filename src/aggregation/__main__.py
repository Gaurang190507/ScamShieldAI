"""CLI demonstration and interactive runner for ScamShield AI Phase 8.

Usage:
    python -m src.aggregation --demo
    python -m src.aggregation --text "URGENT: Your account has been suspended. Verify at http://192.168.1.1/login"
"""

import argparse
import json
import sys
from typing import List

from .pipeline import CaseAssessmentPipeline


DEMO_CASES: List[str] = [
    (
        "URGENT: Your bank account has been suspended due to suspicious activity. "
        "Click http://192.168.1.1/verify?id=99281 to verify your password immediately or funds will be seized."
    ),
    (
        "Hey Mom, I will be home around 6pm for dinner. Can you pick up some groceries on your way back?"
    ),
    (
        "Congratulations! You won a brand new car in our lottery draw. "
        "Please visit our official community page at http://example.com/welcome"
    ),
    (
        "Meeting reminder: the team standup is scheduled tomorrow morning at 10:00 AM. Please review docs at http://192.168.0.1/doc"
    ),
    (
        "Kindly approve the decentralized hyper-ledger staking validator token deployment protocol by midnight."
    ),
]


def run_demo() -> None:
    """Runs demonstration cases showcasing multi-signal risk aggregation."""
    print("=" * 80)
    print("ScamShield AI — Phase 8: Multi-Signal Risk Aggregation & Forensic Audit")
    print("=" * 80)
    print("Initializing pipeline (offline, deterministic)...\n")

    pipeline = CaseAssessmentPipeline(enable_semantic=True)

    for i, text in enumerate(DEMO_CASES, 1):
        print("-" * 80)
        print(f"DEMO CASE {i}:")
        print(f"Message: \"{text}\"")
        print("-" * 80)

        result = pipeline.analyze(text=text, sample_id=f"demo_case_{i:03d}")

        print(f"Status:             {result.assessment.status.upper()}")
        print(f"Evidence Level:     {result.assessment.evidence_level.upper()}")
        print(f"Consistency:        {result.assessment.signal_consistency}")
        print(f"Decision Rule:      {result.audit.final_decision_rule}")
        print(f"Network Access:     {result.audit.network_access}")
        print(f"Phase 5 Used:       {result.audit.phase5_used}")
        print("\nSignals Summary:")
        for sig_grp, sig_val in result.signals.items():
            print(f"  - {sig_grp}: {sig_val}")

        print(f"\nEvidence Items ({len(result.evidence)}):")
        for ev in result.evidence:
            val_str = f" (value: {ev.value})" if ev.value is not None else ""
            txt_str = f" [text: '{ev.text}']" if ev.text else ""
            print(f"  * [{ev.source}] {ev.name}{val_str}{txt_str} -> {ev.reason}")

        print("\nExplanation:")
        print(f"  Summary: {result.explanation.summary}")
        if result.explanation.reasons:
            print("  Reasons:")
            for r in result.explanation.reasons:
                print(f"    - {r}")
        if result.explanation.cautions:
            print("  Cautions:")
            for c in result.explanation.cautions:
                print(f"    ! {c}")

        print("\n")


def main() -> None:
    """CLI entry point."""
    parser = argparse.ArgumentParser(
        description="ScamShield AI Phase 8 Multi-Signal Risk Aggregator"
    )
    parser.add_argument(
        "--demo", action="store_true", help="Run predefined demonstration test cases."
    )
    parser.add_argument(
        "--text", type=str, default=None, help="Evaluate a single message string."
    )
    parser.add_argument(
        "--json", action="store_true", help="Output result as JSON."
    )

    args = parser.parse_args()

    if args.demo:
        run_demo()
    elif args.text:
        pipeline = CaseAssessmentPipeline(enable_semantic=True)
        result = pipeline.analyze(text=args.text)
        if args.json:
            print(json.dumps(result.to_dict(), indent=2))
        else:
            print(f"Status:         {result.assessment.status}")
            print(f"Evidence Level: {result.assessment.evidence_level}")
            print(f"Consistency:    {result.assessment.signal_consistency}")
            print(f"Rule:           {result.audit.final_decision_rule}")
            print(f"Summary:        {result.explanation.summary}")
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
