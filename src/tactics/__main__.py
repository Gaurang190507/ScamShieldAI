"""CLI demonstration entry point for ScamShield AI tactic detection.

Usage:
    python -m src.tactics "Message to analyze..."
    python -m src.tactics --demo
"""

import argparse
import json
import sys
from typing import List

from .tactic_detector import TacticDetector


def run_demo() -> None:
    """Runs tactic detector over representative scam, legitimate, and boundary messages."""
    detector = TacticDetector()
    print("=" * 80)
    print(" ScamShield AI — Phase 6 Tactic Detection & Evidence Extraction Demo")
    print(f" Registered Rules: {detector.rule_count}")
    print("=" * 80)

    demo_messages: List[str] = [
        "Your SBI account will be blocked today. Verify your account immediately using this link: http://bit.ly/sbi-kyc",
        "Electricity Department: Your power connection will be disconnected tonight at 9:30 PM due to unpaid bill of Rs 1450. Pay immediately.",
        "Congratulations! You have won a cash prize of Rs 25,00,000 in KBC Lucky Draw. Call now to claim your prize reward.",
        "State Police Cyber Cell: Under Section 144B, an arrest warrant has been issued. Do not inform anyone. Transfer Rs 50000 immediately.",
        "Work from home job: Earn Rs 3000 daily by liking YouTube videos. Simple task with daily payout guaranteed.",
        "Dear customer, please download AnyDesk so our tech support can resolve your computer virus.",
        "Your electricity bill of Rs 450 is due tomorrow. Please pay before due date to avoid late fee.",
        "Use the OTP 482910 sent to your registered mobile number to complete your transaction. Do not share this OTP with anyone.",
        "Your parcel has been delivered to your front porch. Thank you for shopping with us.",
    ]

    for i, msg in enumerate(demo_messages, 1):
        result = detector.detect(msg, sample_id=f"demo_{i:03d}")
        print(f"\n--- [Message {i}] ---")
        print(f"Text: \"{msg}\"")
        print(f"Tactics Detected: {result.tactic_count}")
        for t in result.tactics:
            print(f"  • [{t.severity.upper()}] {t.tactic} (strength: {t.evidence_strength}):")
            for e in t.evidence:
                print(f"      - \"{e.matched_text}\" (offsets: {e.start}-{e.end}, rule: {e.rule_id})")
                print(f"        Reason: {e.reason}")

    print("\n" + "=" * 80)
    print(" Demo execution complete. Zero network requests made.")
    print("=" * 80)


def main() -> None:
    """CLI entry point parsing arguments."""
    parser = argparse.ArgumentParser(
        description="ScamShield AI Phase 6 Tactic Detection & Evidence Extraction"
    )
    parser.add_argument(
        "message",
        nargs="?",
        default=None,
        help="Input message text to analyze for scam tactics",
    )
    parser.add_argument(
        "--demo",
        action="store_true",
        help="Run interactive demonstration over sample messages",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Output results in JSON format",
    )

    args = parser.parse_args()

    if args.demo or args.message is None:
        run_demo()
        return

    detector = TacticDetector()
    result = detector.detect(args.message)

    if args.json:
        print(json.dumps(result.to_dict(), indent=2, ensure_ascii=False))
    else:
        print(f"Input: \"{result.text}\"")
        print(f"Detected Tactics ({result.tactic_count}):")
        for t in result.tactics:
            print(f"  [{t.severity.upper()}] {t.tactic}:")
            for e in t.evidence:
                print(f"    - \"{e.matched_text}\" [{e.start}:{e.end}] ({e.rule_id}) -> {e.reason}")


if __name__ == "__main__":
    main()
