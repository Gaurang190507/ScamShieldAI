"""Deterministic, reproducible selection of candidates for the ScamShield AI Annotation Pilot.

Extracts a balanced, diverse cohort of 60 real messages from the UCI SMS dataset
to stress-test annotation guidelines across:
- Obvious non-scams (personal/social)
- Hard negatives (legitimate messages with urgency, billing, or security words)
- Obvious scams (phishing links, fake rewards, impersonation)
- Commercial spam (testing the spam != scam boundary)
- Ambiguous / terse messages (testing uncertainty handling)
"""

from pathlib import Path
import json
import re
from typing import List, Dict, Any


def select_pilot_cohort(processed_path: Path, target_count: int = 60) -> List[Dict[str, Any]]:
    """Selects a diverse, deterministic subset of records for pilot annotation.

    Args:
        processed_path: Path to uci_sms_spam.jsonl
        target_count: Total target samples (default 60).

    Returns:
        List of selected unannotated pilot candidate dictionaries.
    """
    with open(processed_path, "r", encoding="utf-8") as f:
        records = [json.loads(line) for line in f]

    selected: List[Dict[str, Any]] = []
    seen_ids = set()

    def add_candidates(candidate_pool: List[Dict[str, Any]], count: int, category_tag: str):
        added = 0
        for r in candidate_pool:
            if r["sample_id"] not in seen_ids:
                r_copy = dict(r)
                r_copy["pilot_sampling_strata"] = category_tag
                selected.append(r_copy)
                seen_ids.add(r["sample_id"])
                added += 1
                if added >= count:
                    break

    # 1. Clear benign messages (conversational / personal / social)
    plain_ham = [
        r for r in records
        if r["label"] == "non_scam"
        and not r["has_url"]
        and not r["has_phone_number"]
        and not r["has_payment_request"]
        and len(r["text"].split()) > 5
    ]
    add_candidates(plain_ham, 15, "benign_conversational")

    # 2. Hard Negatives: Legitimate messages with urgent language
    urgent_words = re.compile(r"\b(urgent|hurry|asap|now|immediately|today|quick|late|call\s+me)\b", re.I)
    urgent_ham = [
        r for r in records
        if r["label"] == "non_scam" and urgent_words.search(r["text"])
    ]
    add_candidates(urgent_ham, 8, "hard_negative_urgency")

    # 3. Hard Negatives: Legitimate messages with financial / billing terms
    fin_words = re.compile(r"\b(bank|bill|balance|card|account|credit|cost|pay|transfer)\b", re.I)
    financial_ham = [
        r for r in records
        if r["label"] == "non_scam" and fin_words.search(r["text"])
    ]
    add_candidates(financial_ham, 7, "hard_negative_financial")

    # 4. Obvious scams with web links (phishing / malicious redirection)
    scams_with_url = [
        r for r in records
        if r["label"] == "scam" and r["has_url"]
    ]
    add_candidates(scams_with_url, 12, "scam_with_url")

    # 5. Obvious scams with high-value rewards / lotteries / claims
    reward_words = re.compile(r"\b(won|winner|claim|prize|cash|£\d+|congratulations|reward|gift)\b", re.I)
    reward_scams = [
        r for r in records
        if r["label"] == "scam" and reward_words.search(r["text"]) and not r["has_url"]
    ]
    add_candidates(reward_scams, 8, "scam_lottery_reward")

    # 6. Commercial Spam boundary (unsolicited marketing, but NOT a coercive scam)
    promo_words = re.compile(r"\b(ringtone|poly|wallpaper|order|discount|club|chat|horoscope|sexy)\b", re.I)
    commercial_spam = [
        r for r in records
        if r["label"] == "scam" and promo_words.search(r["text"])
    ]
    add_candidates(commercial_spam, 5, "commercial_spam_boundary")

    # 7. Ambiguous / Terse messages (context missing)
    ambiguous = [
        r for r in records
        if len(r["text"].split()) <= 4 and ("?" in r["text"] or "!" in r["text"])
    ]
    add_candidates(ambiguous, 5, "ambiguous_minimal_context")

    return selected[:target_count]


def generate_pilot_template(output_path: Path, candidates: List[Dict[str, Any]]) -> None:
    """Generates an unannotated template JSONL file for annotators."""
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with open(output_path, "w", encoding="utf-8") as f:
        for r in candidates:
            template_rec = {
                "sample_id": r["sample_id"],
                "text": r["text"],
                "language": r["language"],
                "source_type": r["source_type"],
                "source_reference": r["source_reference"],
                "collection_date": r["collection_date"],
                "has_url": r["has_url"],
                "urls": r["urls"],
                "has_phone_number": r["has_phone_number"],
                "has_payment_request": r["has_payment_request"],
                # Fields to be manually completed by annotators:
                "label": "TODO: [scam | non_scam]",
                "scam_category": "TODO: [phishing | impersonation | none | unknown | ...]",
                "tactics": [],  # Multi-label list from controlled vocabulary
                "evidence_spans": [],  # List of {"tactic": str, "evidence": str}
                "requested_action": "TODO: [click_link | send_money | reply | none | ...]",
                "target_asset": "TODO: [money | otp | credentials | none | ...]",
                "urgency_level": "TODO: [none | low | medium | high | extreme]",
                "impersonated_entity": "TODO: [bank | government | courier | none | ...]",
                "label_confidence": "TODO: [high | medium | low]",
                "annotator_id": "annotator_001",
                "pattern_group_id": "unknown",  # Documented unknown pattern group convention
                "known_unknown_status": "known",
                "notes": f"Pilot sampling strata: {r.get('pilot_sampling_strata', 'standard')}",
            }
            f.write(json.dumps(template_rec, ensure_ascii=False) + "\n")


if __name__ == "__main__":
    root = Path(__file__).resolve().parents[2]
    proc_file = root / "data" / "processed" / "uci_sms_spam.jsonl"
    template_file = root / "data" / "evaluation" / "annotation_pilot" / "annotation_template.jsonl"
    pilot_list = select_pilot_cohort(proc_file, target_count=60)
    generate_pilot_template(template_file, pilot_list)
    print(f"Generated pilot template with {len(pilot_list)} samples at: {template_file}")
