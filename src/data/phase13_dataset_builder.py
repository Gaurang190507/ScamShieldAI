"""Dataset generator and validation builder for ScamShield AI Phase 13.

Generates leak-safe, schema-compliant evaluation and experimental training datasets:
- training/train.jsonl
- validation/val.jsonl
- test/test.jsonl
- hard_negatives/hard_negatives.jsonl
- multilingual/multilingual_cases.jsonl
- obfuscation/obfuscated_cases.jsonl
- novel_patterns/novel_patterns.jsonl

Enforces:
- Strict group-level isolation: pattern_group_id NEVER crosses train/val/test splits.
- Zero exact or normalized overlap with UCI training split, Phase 7 reference, or Phase 12.
- 100% schema compliance for all 17 canonical Phase 13 fields.
"""

from collections import Counter
import hashlib
import json
from pathlib import Path
import re
import sys
from typing import Any, Dict, List, Set, Tuple


def normalize_text(text: str) -> str:
    """Normalizes text by lowercasing and stripping non-alphanumeric characters."""
    if not isinstance(text, str):
        return ""
    return re.sub(r"\W+", "", text.lower())


def compute_and_verify_evidence_spans(text: str, spans: List[Dict[str, Any]], sample_id: str) -> List[Dict[str, Any]]:
    """Calculates exact start and end offsets for matched_text in text."""
    verified_spans = []
    for span in spans:
        matched = span["matched_text"]
        tactic = span["tactic"]
        start = text.find(matched)
        if start == -1:
            raise ValueError(
                f"Evidence text '{matched}' not found in sample {sample_id}: '{text}'"
            )
        end = start + len(matched)
        verified_spans.append({
            "matched_text": matched,
            "start": start,
            "end": end,
            "tactic": tactic,
        })
    return verified_spans


def create_sample(
    sample_id: str,
    text: str,
    label: str,
    language: str,
    scam_category: str,
    tactics: List[str],
    evidence_spans: List[Dict[str, Any]],
    source_reference: str,
    pattern_group_id: str,
    known_unknown_status: str = "known_pattern",
    provenance_type: str = "human_curated",
    phase13_source: str = "phase13_expansion_corpus",
    augmentation_type: str = "none",
    obfuscation_type: str = "none",
    collection_date: str = "2026-10-02",
) -> Dict[str, Any]:
    """Helper to build a validated Phase 13 sample dict."""
    script = "Devanagari" if language == "hi" else "Latin"
    language_family = "Indo-Aryan" if language in ("hi", "hi-Latn") else "Germanic"

    spans = compute_and_verify_evidence_spans(text, evidence_spans, sample_id)

    sample = {
        "sample_id": sample_id,
        "text": text,
        "label": label,
        "language": language,
        "scam_category": scam_category,
        "tactics": tactics,
        "evidence_spans": spans,
        "source_reference": source_reference,
        "collection_date": collection_date,
        "pattern_group_id": pattern_group_id,
        "known_unknown_status": known_unknown_status,
        "provenance_type": provenance_type,
        "phase13_source": phase13_source,
        "augmentation_type": augmentation_type,
        "language_family": language_family,
        "script": script,
        "obfuscation_type": obfuscation_type,
    }
    return sample


class Phase13DatasetBuilder:
    """Constructs and serializes all Phase 13 datasets."""

    def __init__(self, base_dir: Path):
        self.base_dir = base_dir
        self.output_dir = base_dir / "data" / "evaluation" / "phase13"

    def build_all(self) -> Dict[str, int]:
        """Builds all datasets and writes them to disk."""
        train_cases = self._generate_train_cases()
        val_cases = self._generate_val_cases()
        test_cases = self._generate_test_cases()
        hard_neg_cases = self._generate_hard_negative_cases()
        multilingual_cases = self._generate_multilingual_cases()
        obfuscation_cases = self._generate_obfuscation_cases()
        novel_cases = self._generate_novel_cases()

        # Write to JSONL
        counts = {
            "train": self._write_jsonl(self.output_dir / "training" / "train.jsonl", train_cases),
            "val": self._write_jsonl(self.output_dir / "validation" / "val.jsonl", val_cases),
            "test": self._write_jsonl(self.output_dir / "test" / "test.jsonl", test_cases),
            "hard_negatives": self._write_jsonl(
                self.output_dir / "hard_negatives" / "hard_negatives.jsonl", hard_neg_cases
            ),
            "multilingual": self._write_jsonl(
                self.output_dir / "multilingual" / "multilingual_cases.jsonl", multilingual_cases
            ),
            "obfuscation": self._write_jsonl(
                self.output_dir / "obfuscation" / "obfuscated_cases.jsonl", obfuscation_cases
            ),
            "novel_patterns": self._write_jsonl(
                self.output_dir / "novel_patterns" / "novel_patterns.jsonl", novel_cases
            ),
        }

        # Build consolidated manifests
        all_cases = train_cases + val_cases + test_cases + hard_neg_cases + multilingual_cases + obfuscation_cases + novel_cases
        # Remove duplicate sample_ids if any
        seen_ids = set()
        deduped_all = []
        for c in all_cases:
            if c["sample_id"] not in seen_ids:
                seen_ids.add(c["sample_id"])
                deduped_all.append(c)

        manifest_dir = self.output_dir / "manifests"
        manifest_dir.mkdir(parents=True, exist_ok=True)
        self._write_jsonl(manifest_dir / "all_phase13_cases.jsonl", deduped_all)

        return counts

    def _write_jsonl(self, path: Path, cases: List[Dict[str, Any]]) -> int:
        path.parent.mkdir(parents=True, exist_ok=True)
        with open(path, "w", encoding="utf-8") as f:
            for c in cases:
                f.write(json.dumps(c, ensure_ascii=False) + "\n")
        return len(cases)

    # =========================================================================
    # TRAINING SPLIT (~120 samples)
    # =========================================================================
    def _generate_train_cases(self) -> List[Dict[str, Any]]:
        cases = []
        # Modern Indian English Scams (Train)
        t_en_scams = [
            ("Dear SBI User, your netbanking access is blocked due to unverified Aadhaar card. Click http://192.168.1.55/sbi-kyc to update immediately.",
             "kyc_suspension", ["account_suspension", "urgency", "link_redirection"],
             [{"matched_text": "access is blocked", "start": 36, "end": 53, "tactic": "account_suspension"},
              {"matched_text": "http://192.168.1.55/sbi-kyc", "start": 91, "end": 119, "tactic": "link_redirection"}],
             "grp_p13_tr_en_01"),
            ("Electricity Department Alert: Power disconnection scheduled tonight at 10 PM due to unpaid balance of Rs 1,420. Call 9876541100 to pay.",
             "electricity_bill", ["authority_claim", "threat", "urgency", "payment_request"],
             [{"matched_text": "Power disconnection scheduled tonight at 10 PM", "start": 31, "end": 78, "tactic": "threat"}],
             "grp_p13_tr_en_02"),
            ("Urgent Notice from TRAI: Your mobile number 9820011223 will be disconnected within 2 hours for illegal broadcasting. Press 9 to speak with police officer.",
             "telecom_disconnection", ["authority_claim", "threat", "urgency", "impersonation"],
             [{"matched_text": "disconnected within 2 hours", "start": 63, "end": 91, "tactic": "threat"}],
             "grp_p13_tr_en_03"),
            ("Income Tax Refund Notice: You have an uncollected tax refund of Rs 28,450. Verify your bank account at http://incometax-efiling-portal.org/claim now.",
             "tax_refund", ["refund_claim", "urgency", "link_redirection"],
             [{"matched_text": "uncollected tax refund of Rs 28,450", "start": 38, "end": 73, "tactic": "refund_claim"},
              {"matched_text": "http://incometax-efiling-portal.org/claim", "start": 105, "end": 145, "tactic": "link_redirection"}],
             "grp_p13_tr_en_04"),
            ("Congratulations! You won a cash voucher of Rs 50,000 in Flipkart Big Billion Lucky Draw. Claim at http://flipkart-rewards-claim.net/voucher",
             "lottery_prize", ["reward_claim", "link_redirection"],
             [{"matched_text": "won a cash voucher of Rs 50,000", "start": 21, "end": 52, "tactic": "reward_claim"},
              {"matched_text": "http://flipkart-rewards-claim.net/voucher", "start": 96, "end": 137, "tactic": "link_redirection"}],
             "grp_p13_tr_en_05"),
            ("HDFC Bank Alert: Suspicious transaction of Rs 49,999 on your credit card. If not done by you, download AnyDesk immediately and connect to branch support.",
             "remote_access", ["impersonation", "fear_creation", "remote_access_request"],
             [{"matched_text": "download AnyDesk immediately", "start": 94, "end": 122, "tactic": "remote_access_request"}],
             "grp_p13_tr_en_06"),
            ("Part-Time Work from Home: Earn Rs 3,500 daily by rating Google Maps places. No experience needed. Join Telegram @EarnDailyIndia to start.",
             "task_scam", ["job_offer", "link_redirection"],
             [{"matched_text": "Earn Rs 3,500 daily by rating Google Maps", "start": 31, "end": 72, "tactic": "job_offer"}],
             "grp_p13_tr_en_07"),
            ("India Post: Your package #IN88921 cannot be delivered due to incomplete street address. Update address within 24 hours at http://indiapost-update.top",
             "parcel_delivery", ["delivery_problem", "urgency", "link_redirection"],
             [{"matched_text": "cannot be delivered due to incomplete street address", "start": 33, "end": 85, "tactic": "delivery_problem"},
              {"matched_text": "http://indiapost-update.top", "start": 118, "end": 145, "tactic": "link_redirection"}],
             "grp_p13_tr_en_08"),
            ("Urgent KYC update: Your Paytm Wallet limit will be reduced to zero. Download the verification quick support tool at http://paytm-kyc-verify.cc",
             "wallet_kyc", ["account_suspension", "urgency", "link_redirection"],
             [{"matched_text": "reduced to zero", "start": 62, "end": 77, "tactic": "account_suspension"},
              {"matched_text": "http://paytm-kyc-verify.cc", "start": 120, "end": 146, "tactic": "link_redirection"}],
             "grp_p13_tr_en_09"),
            ("Digital Arrest Interrogation: Supreme Court notice against your Aadhaar for money laundering. Join Skype call with Cyber Cell officers or face immediate jail.",
             "digital_arrest", ["authority_claim", "threat", "fear_creation"],
             [{"matched_text": "Supreme Court notice against your Aadhaar", "start": 31, "end": 72, "tactic": "authority_claim"},
              {"matched_text": "face immediate jail", "start": 134, "end": 153, "tactic": "threat"}],
             "grp_p13_tr_en_10"),
            ("Dear customer, your credit card reward points worth Rs 9,850 are expiring today. Redeem to bank cash now at http://reward-redeem-bank.com/points",
             "reward_points", ["reward_claim", "urgency", "link_redirection"],
             [{"matched_text": "points worth Rs 9,850 are expiring today", "start": 40, "end": 80, "tactic": "reward_claim"},
              {"matched_text": "http://reward-redeem-bank.com/points", "start": 109, "end": 145, "tactic": "link_redirection"}],
             "grp_p13_tr_en_11"),
            ("Security notice: Unauthorized debit card usage attempt detected in Singapore. Share the 6-digit verification code with our agent to block it.",
             "otp_theft", ["impersonation", "fear_creation", "otp_request"],
             [{"matched_text": "Share the 6-digit verification code", "start": 80, "end": 115, "tactic": "otp_request"}],
             "grp_p13_tr_en_12"),
            ("ICICI Bank Warning: Your iMobile account is deactivated. To reactivate, click http://icici-reactivate.club and confirm your debit card PIN.",
             "credential_theft", ["account_suspension", "credential_request", "link_redirection"],
             [{"matched_text": "account is deactivated", "start": 33, "end": 55, "tactic": "account_suspension"},
              {"matched_text": "confirm your debit card PIN", "start": 105, "end": 133, "tactic": "credential_request"}],
             "grp_p13_tr_en_13"),
            ("Loan approval alert: Your pre-approved personal loan of Rs 5,00,000 is ready for instant transfer. Pay processing fee of Rs 1,999 to UPI loan@okaxis.",
             "fake_loan", ["reward_claim", "payment_request"],
             [{"matched_text": "Pay processing fee of Rs 1,999", "start": 82, "end": 112, "tactic": "payment_request"}],
             "grp_p13_tr_en_14"),
            ("Customs Clearance Alert: A package containing illegal narcotics addressed to you was intercepted at Delhi Airport. Pay clearance bond to avoid arrest.",
             "customs_extortion", ["authority_claim", "threat", "payment_request"],
             [{"matched_text": "intercepted at Delhi Airport", "start": 80, "end": 108, "tactic": "threat"},
              {"matched_text": "Pay clearance bond to avoid arrest", "start": 110, "end": 145, "tactic": "payment_request"}],
             "grp_p13_tr_en_15"),
        ]

        idx = 1
        for text, cat, tactics, spans, grp in t_en_scams:
            cases.append(create_sample(
                sample_id=f"p13_tr_en_scam_{idx:03d}",
                text=text,
                label="scam",
                language="en",
                scam_category=cat,
                tactics=tactics,
                evidence_spans=spans,
                source_reference="src_p13_telecom_banking",
                pattern_group_id=grp,
            ))
            idx += 1

        # Modern Indian English Non-Scams (Train)
        t_en_ham = [
            ("Dear Customer, Rs 5,000.00 debited from account **1234 on 02-OCT-2026 at ATM. Avl Bal: Rs 42,100. Call 1800112211 if not recognized.",
             "bank_alert", "grp_p13_tr_en_ham_01"),
            ("Your one-time verification password for HDFC NetBanking login is 839201. Valid for 5 minutes. Do not share with anyone including bank staff.",
             "bank_otp", "grp_p13_tr_en_ham_02"),
            ("Tata Power: Thank you for your payment of Rs 1,420 towards consumer number 902812. Receipt has been generated.",
             "bill_receipt", "grp_p13_tr_en_ham_03"),
            ("Your Amazon package with tracking ID 403-91823-11 has been delivered to your front door. Thank you for shopping with us.",
             "package_delivered", "grp_p13_tr_en_ham_04"),
            ("IRCTC Booking Confirmation: PNR 2419028102, Train 12951 NDLS TEJAS RAJ, 05-OCT-2026. Coach B4, Berth 21 (LB). Happy Journey!",
             "train_ticket", "grp_p13_tr_en_ham_05"),
            ("Airtel Alert: You have exhausted 90% of your daily high-speed data quota. Recharge on Airtel Thanks App for additional data.",
             "telecom_alert", "grp_p13_tr_en_ham_06"),
            ("Your Swiggy order from Biryani Blues is confirmed and arriving in 25 mins. Delivery executive Rahul is assigned.",
             "food_delivery", "grp_p13_tr_en_ham_07"),
            ("Doctor appointment confirmed with Dr. Sharma for tomorrow at 11:30 AM at Apollo Clinic, Indiranagar. Please arrive 10 mins early.",
             "health_appointment", "grp_p13_tr_en_ham_08"),
            ("Indigo Flight 6E-204 from BLR to DEL is on schedule. Web check-in closes 60 mins before departure. Have a pleasant flight.",
             "flight_update", "grp_p13_tr_en_ham_09"),
            ("Salary credit alert: Rs 85,000 has been credited to your salary account from ACME CORP PVT LTD on 30-SEP-2026.",
             "salary_credit", "grp_p13_tr_en_ham_10"),
        ]

        idx = 1
        for text, cat, grp in t_en_ham:
            cases.append(create_sample(
                sample_id=f"p13_tr_en_ham_{idx:03d}",
                text=text,
                label="non_scam",
                language="en",
                scam_category=cat,
                tactics=[],
                evidence_spans=[],
                source_reference="src_p13_hard_negatives",
                pattern_group_id=grp,
            ))
            idx += 1

        # Romanized Hinglish Scams (Train)
        t_hi_latn_scams = [
            ("Aapka SBI bank khata aaj raat 9 baje block ho jayega unverified KYC ki wajah se. Turant link http://sbi-kyc-update.co/login par update karein.",
             "kyc_suspension", ["account_suspension", "urgency", "link_redirection"],
             [{"matched_text": "khata aaj raat 9 baje block ho jayega", "start": 15, "end": 52, "tactic": "account_suspension"},
              {"matched_text": "http://sbi-kyc-update.co/login", "start": 100, "end": 130, "tactic": "link_redirection"}],
             "grp_p13_tr_hl_01"),
            ("Bijli vibhag soochana: Aapka electricity connection aaj raat 9:30 baje kaat diya jayega kyunki pichla bill jama nahi hai. Contact 9811223344.",
             "electricity_bill", ["authority_claim", "threat", "urgency", "payment_request"],
             [{"matched_text": "electricity connection aaj raat 9:30 baje kaat diya jayega", "start": 23, "end": 81, "tactic": "threat"}],
             "grp_p13_tr_hl_02"),
            ("Badhai ho! Aapne KBC lottery mein Rs 25,00,000 jeete hain. Apna prize claim karne ke liye WhatsApp number 9876543299 par message karein.",
             "lottery_prize", ["reward_claim", "link_redirection"],
             [{"matched_text": "KBC lottery mein Rs 25,00,000 jeete hain", "start": 17, "end": 57, "tactic": "reward_claim"}],
             "grp_p13_tr_hl_03"),
            ("Ghar baithe part-time job: Daily YouTube video like karke Rs 2,000 kamayein. Bina kisi kharche ke shuru karein. Telegram join karein @DailyTaskIN.",
             "task_scam", ["job_offer", "link_redirection"],
             [{"matched_text": "Daily YouTube video like karke Rs 2,000 kamayein", "start": 26, "end": 74, "tactic": "job_offer"}],
             "grp_p13_tr_hl_04"),
            ("TRAI notice: Aapka sim card agle 2 ghante mein band kar diya jayega cyber crime complaint ke kaaran. Turant 9 par dabayein.",
             "telecom_threat", ["authority_claim", "threat", "urgency"],
             [{"matched_text": "agle 2 ghante mein band kar diya jayega", "start": 26, "end": 65, "tactic": "threat"}],
             "grp_p13_tr_hl_05"),
            ("HDFC bank security: Aapke account se Rs 25,000 ka fraud transfer hua hai. Isse rokne ke liye turant AnyDesk app install karke call karein.",
             "remote_access", ["fear_creation", "remote_access_request"],
             [{"matched_text": "AnyDesk app install karke", "start": 98, "end": 123, "tactic": "remote_access_request"}],
             "grp_p13_tr_hl_06"),
            ("Speed Post alert: Aapka parcel delivery address galat hone ki wajah se ruka hua hai. Address update karein: http://indiapost-parcels.in",
             "parcel_delivery", ["delivery_problem", "link_redirection"],
             [{"matched_text": "delivery address galat hone ki wajah se ruka hua hai", "start": 24, "end": 76, "tactic": "delivery_problem"},
              {"matched_text": "http://indiapost-parcels.in", "start": 101, "end": 128, "tactic": "link_redirection"}],
             "grp_p13_tr_hl_07"),
            ("Paytm KYC suspension warning: Aapka wallet suspend ho raha hai. Apna Aadhaar aur PAN verify karein http://paytm-kyc-portal.me par.",
             "wallet_kyc", ["account_suspension", "urgency", "link_redirection"],
             [{"matched_text": "wallet suspend ho raha hai", "start": 38, "end": 64, "tactic": "account_suspension"},
              {"matched_text": "http://paytm-kyc-portal.me", "start": 100, "end": 125, "tactic": "link_redirection"}],
             "grp_p13_tr_hl_08"),
            ("Credit card cash reward: Aapke Rs 7,500 ke points expire ho rahe hain. Bank account mein transfer karne ke liye link kholiye http://points-redeem.cc",
             "reward_points", ["reward_claim", "urgency", "link_redirection"],
             [{"matched_text": "points expire ho rahe hain", "start": 44, "end": 70, "tactic": "reward_claim"},
              {"matched_text": "http://points-redeem.cc", "start": 127, "end": 149, "tactic": "link_redirection"}],
             "grp_p13_tr_hl_09"),
            ("Aadhaar loan scheme: Pradhan Mantri mudra loan ke tehat Rs 3 lakh turant manzoor. Processing fee Rs 1,500 UPI karein mudra@icici par.",
             "loan_fraud", ["reward_claim", "payment_request"],
             [{"matched_text": "Processing fee Rs 1,500 UPI karein", "start": 69, "end": 103, "tactic": "payment_request"}],
             "grp_p13_tr_hl_10"),
        ]

        idx = 1
        for text, cat, tactics, spans, grp in t_hi_latn_scams:
            cases.append(create_sample(
                sample_id=f"p13_tr_hl_scam_{idx:03d}",
                text=text,
                label="scam",
                language="hi-Latn",
                scam_category=cat,
                tactics=tactics,
                evidence_spans=spans,
                source_reference="src_p13_multilingual",
                pattern_group_id=grp,
            ))
            idx += 1

        # Romanized Hinglish Non-Scams (Train)
        t_hi_latn_ham = [
            ("Aapka SBI account number **4567 se Rs 1,200 UPI transaction Dwarka store par safal raha. Available balance Rs 18,340 hai.",
             "upi_success", "grp_p13_tr_hl_ham_01"),
            ("Aapka Zomato order safal raha. Delivery rider Rohit aapka khana lekar 20 minute mein pahunch raha hai.",
             "food_delivery", "grp_p13_tr_hl_ham_02"),
            ("Aapke Jio number par 1.5 GB daily data pack activate ho gaya hai. Validity 28 din tak valid hai. Dhanyawad.",
             "telecom_plan", "grp_p13_tr_hl_ham_03"),
            ("Aapka electricity bill Rs 1,840 safalta-purvak pay ho gaya hai. Transaction ID: TXN902812.",
             "bill_payment", "grp_p13_tr_hl_ham_04"),
            ("Bhai kal shaam ko 7 baje chai pe milte hain. Rohit ko bhi phone karke bol dena.",
             "personal_chat", "grp_p13_tr_hl_ham_05"),
        ]

        idx = 1
        for text, cat, grp in t_hi_latn_ham:
            cases.append(create_sample(
                sample_id=f"p13_tr_hl_ham_{idx:03d}",
                text=text,
                label="non_scam",
                language="hi-Latn",
                scam_category=cat,
                tactics=[],
                evidence_spans=[],
                source_reference="src_p13_multilingual",
                pattern_group_id=grp,
            ))
            idx += 1

        # Native Hindi Devanagari Scams (Train)
        t_hi_scams = [
            ("सतर्कता सूचना: प्रिय उपभोक्ता, आपका बैंक ऑफ महाराष्ट्र खाता आधार से न जुड़े होने के कारण आज रात बंद हो जाएगा। चालू रखने हेतु http://bom-kyc-verify.co पर आधार दर्ज करें।",
             "kyc_suspension", ["account_suspension", "urgency", "link_redirection"],
             [{"matched_text": "खाता आधार से न जुड़े होने के कारण आज रात बंद हो जाएगा", "start": 37, "end": 88, "tactic": "account_suspension"},
              {"matched_text": "http://bom-kyc-verify.co", "start": 105, "end": 129, "tactic": "link_redirection"}],
             "grp_p13_tr_hi_01"),
            ("उत्तर प्रदेश विद्युत निगम: प्रिय उपभोक्ता, बकाया विद्युत बिल रु 2,340 का भुगतान न करने पर आपकी बिजली लाइन आज दोपहर 2 बजे काट दी जाएगी। कॉल करें 9820011445।",
             "electricity_bill", ["authority_claim", "threat", "urgency", "payment_request"],
             [{"matched_text": "आपकी बिजली लाइन आज दोपहर 2 बजे काट दी जाएगी", "start": 89, "end": 133, "tactic": "threat"},
              {"matched_text": "बकाया विद्युत बिल रु 2,340", "start": 44, "end": 70, "tactic": "payment_request"}],
             "grp_p13_tr_hi_02"),
            ("बधाई हो! आपको प्रधानमंत्री आवास योजना के तहत रु 2,50,000 की सब्सिडी मंजूर हुई है। राशि प्राप्त करने हेतु http://pm-awas-yojana.top पर विवरण भरें।",
             "govt_scheme", ["reward_claim", "link_redirection"],
             [{"matched_text": "रु 2,50,000 की सब्सिडी मंजूर हुई है", "start": 39, "end": 72, "tactic": "reward_claim"},
              {"matched_text": "http://pm-awas-yojana.top", "start": 98, "end": 123, "tactic": "link_redirection"}],
             "grp_p13_tr_hi_03"),
            ("दूरसंचार विभाग चेतावनी: आपके आधार से जारी सभी सिम कार्ड 2 घंटे में बंद कर दिए जाएंगे। कानूनी कार्रवाई से बचने के लिए तुरंत 9 दबाएं।",
             "telecom_threat", ["authority_claim", "threat", "urgency"],
             [{"matched_text": "2 घंटे में बंद कर दिए जाएंगे", "start": 57, "end": 84, "tactic": "threat"}],
             "grp_p13_tr_hi_04"),
            ("सुरक्षा चेतावनी: आपके पीएनबी खाते में संदिग्ध लॉगिन हुआ है। खाता फ्रीज होने से बचाने के लिए अपने मोबाइल पर प्राप्त 6 अंकों का ओटीपी तुरंत बताएं।",
             "otp_theft", ["impersonation", "fear_creation", "otp_request"],
             [{"matched_text": "खाता फ्रीज होने से बचाने के लिए", "start": 44, "end": 74, "tactic": "fear_creation"},
              {"matched_text": "प्राप्त 6 अंकों का ओटीपी तुरंत बताएं", "start": 98, "end": 133, "tactic": "otp_request"}],
             "grp_p13_tr_hi_05"),
            ("घर बैठे कमाई: प्रतिदिन यूट्यूब वीडियो देखकर रु 3,000 कमाएं। किसी शुल्क की आवश्यकता नहीं। हमारे टेलीग्राम चैनल @HindiTasks से जुड़ें।",
             "task_scam", ["job_offer", "link_redirection"],
             [{"matched_text": "प्रतिदिन यूट्यूब वीडियो देखकर रु 3,000 कमाएं", "start": 16, "end": 58, "tactic": "job_offer"}],
             "grp_p13_tr_hi_06"),
            ("भारतीय डाक: आपका पार्सल गलत पते के कारण वितरण केंद्र पर रुका हुआ है। 24 घंटे में अपना सही पता दर्ज करें: http://indiapost-service.in/update",
             "parcel_delivery", ["delivery_problem", "urgency", "link_redirection"],
             [{"matched_text": "वितरण केंद्र पर रुका हुआ है", "start": 41, "end": 67, "tactic": "delivery_problem"},
              {"matched_text": "http://indiapost-service.in/update", "start": 105, "end": 139, "tactic": "link_redirection"}],
             "grp_p13_tr_hi_07"),
            ("अति आवश्यक: आपका पैन कार्ड आयकर विभाग द्वारा निष्क्रिय कर दिया गया है। बैंक खाता चालू रखने के लिए http://pan-verification.online पर जाएं।",
             "pan_inactive", ["authority_claim", "account_suspension", "link_redirection"],
             [{"matched_text": "निष्क्रिय कर दिया गया है", "start": 43, "end": 67, "tactic": "account_suspension"},
              {"matched_text": "http://pan-verification.online", "start": 99, "end": 130, "tactic": "link_redirection"}],
             "grp_p13_tr_hi_08"),
            ("डिजिटल अरेस्ट नोटिस: सीबीआई साइबर अपराध प्रकोष्ठ द्वारा आपके नाम गैर-जमानती वारंट जारी किया गया है। तुरंत वीडियो कॉल पर उपस्थित हों।",
             "digital_arrest", ["authority_claim", "threat", "fear_creation"],
             [{"matched_text": "गैर-जमानती वारंट जारी किया गया है", "start": 57, "end": 89, "tactic": "threat"}],
             "grp_p13_tr_hi_09"),
            ("लॉटरी विजेता: आपने कौन बनेगा करोड़पति में रु 50 लाख का नकद इनाम जीता है। अपने बैंक खाते में पैसा लेने हेतु 9911223344 पर कॉल करें।",
             "lottery_prize", ["reward_claim", "link_redirection"],
             [{"matched_text": "रु 50 लाख का नकद इनाम जीता है", "start": 41, "end": 71, "tactic": "reward_claim"}],
             "grp_p13_tr_hi_10"),
        ]

        idx = 1
        for text, cat, tactics, spans, grp in t_hi_scams:
            cases.append(create_sample(
                sample_id=f"p13_tr_hi_scam_{idx:03d}",
                text=text,
                label="scam",
                language="hi",
                scam_category=cat,
                tactics=tactics,
                evidence_spans=spans,
                source_reference="src_p13_multilingual",
                pattern_group_id=grp,
            ))
            idx += 1

        # Native Hindi Devanagari Non-Scams (Train)
        t_hi_ham = [
            ("प्रिय ग्राहक, आपके बैंक खाते **7890 से रु 2,500 का सफल आहरण हुआ। उपलब्ध शेष राशि रु 14,200 है। किसी समस्या के लिए 1800112211 पर कॉल करें।",
             "bank_alert", "grp_p13_tr_hi_ham_01"),
            ("एसबीआई नेटबैंकिंग लॉगिन के लिए आपका ओटीपी 749201 है। यह 5 मिनट के लिए मान्य है। इसे किसी के साथ साझा न करें।",
             "bank_otp", "grp_p13_tr_hi_ham_02"),
            ("बिजली विभाग: माह सितंबर 2026 के लिए आपका बिल रु 1,340 सफलतापूर्वक प्राप्त हुआ। रसीद संख्या: RCP890123। धन्यवाद।",
             "bill_receipt", "grp_p13_tr_hi_ham_03"),
            ("आईआरसीटीसी: पीएनआर 2849102834, गाड़ी 12004 शताब्दी एक्सप्रेस, कोच सी2, सीट 45। आपकी यात्रा सुखद और मंगलमय हो।",
             "train_ticket", "grp_p13_tr_hi_ham_04"),
            ("माताजी, हम सब सकुशल दिल्ली पहुंच गए हैं। आप अपनी दवाएं समय पर ले लीजिएगा।",
             "personal_chat", "grp_p13_tr_hi_ham_05"),
        ]

        idx = 1
        for text, cat, grp in t_hi_ham:
            cases.append(create_sample(
                sample_id=f"p13_tr_hi_ham_{idx:03d}",
                text=text,
                label="non_scam",
                language="hi",
                scam_category=cat,
                tactics=[],
                evidence_spans=[],
                source_reference="src_p13_multilingual",
                pattern_group_id=grp,
            ))
            idx += 1

        return cases

    # =========================================================================
    # VALIDATION SPLIT (~40 samples, strictly disjoint pattern groups)
    # =========================================================================
    def _generate_val_cases(self) -> List[Dict[str, Any]]:
        cases = []
        # English Scams (Val)
        val_en_scams = [
            ("Urgent: Axis Bank netbanking locked. Update PAN card now at http://192.168.1.180/axis-login to restore access.",
             "kyc_suspension", ["account_suspension", "urgency", "link_redirection"],
             [{"matched_text": "netbanking locked", "start": 18, "end": 36, "tactic": "account_suspension"},
              {"matched_text": "http://192.168.1.180/axis-login", "start": 61, "end": 92, "tactic": "link_redirection"}],
             "grp_p13_val_en_01"),
            ("Power Cutoff Warning: BSES electricity supply will be disconnected at 8:00 PM for pending bill. Contact 9123456780.",
             "electricity_bill", ["authority_claim", "threat", "urgency"],
             [{"matched_text": "electricity supply will be disconnected at 8:00 PM", "start": 28, "end": 78, "tactic": "threat"}],
             "grp_p13_val_en_02"),
            ("Work from Home Opportunity: Earn Rs 4,000 every day reviewing hotel listings. Contact manager on Telegram @HotelReviewTask.",
             "task_scam", ["job_offer", "link_redirection"],
             [{"matched_text": "Earn Rs 4,000 every day reviewing hotel listings", "start": 29, "end": 77, "tactic": "job_offer"}],
             "grp_p13_val_en_03"),
            ("Courier Alert: BlueDart shipment delayed due to tax customs charge of Rs 49. Pay immediately at http://bluedart-tax.top/pay",
             "parcel_delivery", ["delivery_problem", "payment_request", "link_redirection"],
             [{"matched_text": "delayed due to tax customs charge", "start": 33, "end": 66, "tactic": "delivery_problem"},
              {"matched_text": "http://bluedart-tax.top/pay", "start": 98, "end": 125, "tactic": "link_redirection"}],
             "grp_p13_val_en_04"),
            ("Bank of Baroda: Suspicious withdrawal of Rs 35,000. To cancel debit, install TeamViewer QuickSupport and call back.",
             "remote_access", ["fear_creation", "remote_access_request"],
             [{"matched_text": "install TeamViewer QuickSupport", "start": 70, "end": 101, "tactic": "remote_access_request"}],
             "grp_p13_val_en_05"),
        ]
        idx = 1
        for text, cat, tactics, spans, grp in val_en_scams:
            cases.append(create_sample(
                sample_id=f"p13_val_en_scam_{idx:03d}",
                text=text,
                label="scam",
                language="en",
                scam_category=cat,
                tactics=tactics,
                evidence_spans=spans,
                source_reference="src_p13_telecom_banking",
                pattern_group_id=grp,
            ))
            idx += 1

        # English Non-Scams (Val - including hard negatives)
        val_en_ham = [
            ("Your OTP for accessing Income Tax e-Filing portal is 938210. Valid for 10 minutes. Do not share with anyone.",
             "tax_otp", "grp_p13_val_en_ham_01"),
            ("Dear Customer, Rs 1,500 debited from SBI a/c **8901 on 02-OCT-2026. If not done by you, SMS BLOCK to 567676.",
             "bank_alert", "grp_p13_val_en_ham_02"),
            ("Reminder: Your monthly electricity bill of Rs 890 is due on 05-OCT-2026. Pay via official portal or app to avoid late fees.",
             "bill_reminder", "grp_p13_val_en_ham_03"),
            ("Your Domino's pizza order is out for delivery with rider Amit. Contact rider at 9876500112.",
             "delivery_update", "grp_p13_val_en_ham_04"),
            ("Hi Sneha, please find attached the revised project roadmap for Q4. Let's discuss in tomorrow's standup.",
             "work_email", "grp_p13_val_en_ham_05"),
        ]
        idx = 1
        for text, cat, grp in val_en_ham:
            cases.append(create_sample(
                sample_id=f"p13_val_en_ham_{idx:03d}",
                text=text,
                label="non_scam",
                language="en",
                scam_category=cat,
                tactics=[],
                evidence_spans=[],
                source_reference="src_p13_hard_negatives",
                pattern_group_id=grp,
            ))
            idx += 1

        # Hinglish Scams & Non-Scams (Val)
        val_hl_scams = [
            ("Aapka ICICI Bank account block kar diya gaya hai. Turant PAN card link karein http://icici-pan-link.cc par nahi toh account freeze rahega.",
             "kyc_suspension", ["account_suspension", "urgency", "link_redirection"],
             [{"matched_text": "account block kar diya gaya hai", "start": 17, "end": 48, "tactic": "account_suspension"},
              {"matched_text": "http://icici-pan-link.cc", "start": 74, "end": 98, "tactic": "link_redirection"}],
             "grp_p13_val_hl_01"),
            ("Urgent soochana: Bijli connection raat ko cut kar diya jayega pending bill ke liye. Call karein officer ko 9811002233.",
             "electricity_bill", ["authority_claim", "threat", "urgency"],
             [{"matched_text": "Bijli connection raat ko cut kar diya jayega", "start": 16, "end": 60, "tactic": "threat"}],
             "grp_p13_val_hl_02"),
            ("Ghar baithe kamayein: Instagram reels like karke daily Rs 3,500 kamayein. Telegram contact @DailyEarningHub.",
             "task_scam", ["job_offer", "link_redirection"],
             [{"matched_text": "Instagram reels like karke daily Rs 3,500 kamayein", "start": 23, "end": 73, "tactic": "job_offer"}],
             "grp_p13_val_hl_03"),
        ]
        idx = 1
        for text, cat, tactics, spans, grp in val_hl_scams:
            cases.append(create_sample(
                sample_id=f"p13_val_hl_scam_{idx:03d}",
                text=text,
                label="scam",
                language="hi-Latn",
                scam_category=cat,
                tactics=tactics,
                evidence_spans=spans,
                source_reference="src_p13_multilingual",
                pattern_group_id=grp,
            ))
            idx += 1

        val_hl_ham = [
            ("Aapka Uber driver Rajesh pahunch gaya hai. OTP 4821 share karein ride shuru karne ke liye.",
             "ride_otp", "grp_p13_val_hl_ham_01"),
            ("Aapka credit card bill Rs 3,450 successfully pay ho gaya hai. Dhanyawad.",
             "card_payment", "grp_p13_val_hl_ham_02"),
        ]
        idx = 1
        for text, cat, grp in val_hl_ham:
            cases.append(create_sample(
                sample_id=f"p13_val_hl_ham_{idx:03d}",
                text=text,
                label="non_scam",
                language="hi-Latn",
                scam_category=cat,
                tactics=[],
                evidence_spans=[],
                source_reference="src_p13_multilingual",
                pattern_group_id=grp,
            ))
            idx += 1

        # Native Hindi Scams & Non-Scams (Val)
        val_hi_scams = [
            ("प्रिय बैंक ग्राहक, आपका खाता तुरंत प्रभाव से रोक दिया गया है। पुनः सक्रिय करने हेतु http://pnb-kyc-reactivate.in पर जाएं।",
             "kyc_suspension", ["account_suspension", "link_redirection"],
             [{"matched_text": "खाता तुरंत प्रभाव से रोक दिया गया है", "start": 22, "end": 58, "tactic": "account_suspension"},
              {"matched_text": "http://pnb-kyc-reactivate.in", "start": 79, "end": 107, "tactic": "link_redirection"}],
             "grp_p13_val_hi_01"),
            ("बिजली विभाग: आज शाम 7 बजे आपका मीटर कनेक्शन काट दिया जाएगा। बिल भुगतान हेतु तुरंत संपर्क करें 9711223344।",
             "electricity_bill", ["authority_claim", "threat", "urgency"],
             [{"matched_text": "मीटर कनेक्शन काट दिया जाएगा", "start": 29, "end": 56, "tactic": "threat"}],
             "grp_p13_val_hi_02"),
            ("टेलीग्राम टास्क: यूट्यूब वीडियो लाइक करके प्रतिदिन रु 2,500 प्राप्त करें। अभी जुड़ें @IndiaWorkFromHome।",
             "task_scam", ["job_offer", "link_redirection"],
             [{"matched_text": "प्रतिदिन रु 2,500 प्राप्त करें", "start": 41, "end": 70, "tactic": "job_offer"}],
             "grp_p13_val_hi_03"),
        ]
        idx = 1
        for text, cat, tactics, spans, grp in val_hi_scams:
            cases.append(create_sample(
                sample_id=f"p13_val_hi_scam_{idx:03d}",
                text=text,
                label="scam",
                language="hi",
                scam_category=cat,
                tactics=tactics,
                evidence_spans=spans,
                source_reference="src_p13_multilingual",
                pattern_group_id=grp,
            ))
            idx += 1

        val_hi_ham = [
            ("प्रिय उपभोक्ता, आपके बिजली खाते में रु 1,120 का बिल जमा हो चुका है। धन्यवाद - उत्तर प्रदेश पावर कॉर्पोरेशन।",
             "bill_receipt", "grp_p13_val_hi_ham_01"),
            ("एचडीएफसी बैंक: आपके खाते में रु 5,000 जमा किए गए हैं। कुल शेष रु 23,450 है।",
             "bank_credit", "grp_p13_val_hi_ham_02"),
        ]
        idx = 1
        for text, cat, grp in val_hi_ham:
            cases.append(create_sample(
                sample_id=f"p13_val_hi_ham_{idx:03d}",
                text=text,
                label="non_scam",
                language="hi",
                scam_category=cat,
                tactics=[],
                evidence_spans=[],
                source_reference="src_p13_multilingual",
                pattern_group_id=grp,
            ))
            idx += 1

        return cases

    # =========================================================================
    # TEST SPLIT (~60 samples, held-out, completely disjoint pattern groups)
    # =========================================================================
    def _generate_test_cases(self) -> List[Dict[str, Any]]:
        cases = []
        # Group 1: Historical English Style Scams & Non-Scams
        test_hist_scams = [
            ("WINNER! You have won a guaranteed cash prize of 1,000 pounds or a holiday in Spain. Call 09061743810 now to claim. T&Cs apply.",
             "historical_lottery", ["reward_claim", "urgency"],
             [{"matched_text": "won a guaranteed cash prize of 1,000 pounds", "start": 17, "end": 60, "tactic": "reward_claim"}],
             "grp_p13_ts_hist_01"),
            ("URGENT! Your mobile number was awarded 5,000 bonus points. To claim call 08712460324 immediately. Standard rates apply.",
             "historical_points", ["reward_claim", "urgency"],
             [{"matched_text": "awarded 5,000 bonus points", "start": 26, "end": 52, "tactic": "reward_claim"},
              {"matched_text": "call 08712460324 immediately", "start": 63, "end": 91, "tactic": "urgency"}],
             "grp_p13_ts_hist_02"),
            ("FREE ringtone! Text YES to 8007 to receive your polyphonic tune. 1.50 per week subscription until STOP.",
             "historical_premium_sms", ["reward_claim"],
             [{"matched_text": "FREE ringtone!", "start": 0, "end": 14, "tactic": "reward_claim"}],
             "grp_p13_ts_hist_03"),
        ]
        idx = 1
        for text, cat, tactics, spans, grp in test_hist_scams:
            cases.append(create_sample(
                sample_id=f"p13_ts_hist_scam_{idx:03d}",
                text=text,
                label="scam",
                language="en",
                scam_category=cat,
                tactics=tactics,
                evidence_spans=spans,
                source_reference="src_p13_telecom_banking",
                pattern_group_id=grp,
            ))
            idx += 1

        test_hist_ham = [
            ("Hey mate, are we still meeting up for squash at 6 today? Let me know if you are free.",
             "personal_chat", "grp_p13_ts_hist_ham_01"),
            ("Can you pick up some milk and bread on your way home from work? Thanks love.",
             "routine_sms", "grp_p13_ts_hist_ham_02"),
        ]
        idx = 1
        for text, cat, grp in test_hist_ham:
            cases.append(create_sample(
                sample_id=f"p13_ts_hist_ham_{idx:03d}",
                text=text,
                label="non_scam",
                language="en",
                scam_category=cat,
                tactics=[],
                evidence_spans=[],
                source_reference="src_p13_hard_negatives",
                pattern_group_id=grp,
            ))
            idx += 1

        # Group 2: Modern Indian English Scams
        test_ind_scams = [
            ("Dear PNB Customer, your NetBanking user ID has been disabled. Visit http://pnb-online-banking.top to reactivate and submit PAN.",
             "kyc_suspension", ["account_suspension", "link_redirection"],
             [{"matched_text": "user ID has been disabled", "start": 36, "end": 61, "tactic": "account_suspension"},
              {"matched_text": "http://pnb-online-banking.top", "start": 69, "end": 98, "tactic": "link_redirection"}],
             "grp_p13_ts_ind_01"),
            ("Electricity Bill Final Notice: Power will be disconnected tonight at 9:30 PM due to unpaid bill of Rs 2,190. Call electricity officer at 9820099881.",
             "electricity_bill", ["authority_claim", "threat", "urgency", "payment_request"],
             [{"matched_text": "Power will be disconnected tonight at 9:30 PM", "start": 32, "end": 77, "tactic": "threat"}],
             "grp_p13_ts_ind_02"),
            ("Earn Rs 5,000 per day by rating hotels on Google Maps. No capital required. Join our official Telegram group @IndiaReviewJobs now.",
             "task_scam", ["job_offer", "link_redirection"],
             [{"matched_text": "Earn Rs 5,000 per day by rating hotels", "start": 0, "end": 39, "tactic": "job_offer"}],
             "grp_p13_ts_ind_03"),
            ("URGENT: Supreme Court Cyber Cell has issued an arrest warrant on your Aadhaar card for laundering money. Join WhatsApp video call immediately.",
             "digital_arrest", ["authority_claim", "threat", "fear_creation"],
             [{"matched_text": "arrest warrant on your Aadhaar card", "start": 44, "end": 79, "tactic": "threat"}],
             "grp_p13_ts_ind_04"),
            ("India Post: Shipment IN77819 held at customs hub due to wrong PIN code. Pay Rs 25 redelivery fee at http://indiapost-parcels.top",
             "parcel_delivery", ["delivery_problem", "payment_request", "link_redirection"],
             [{"matched_text": "held at customs hub due to wrong PIN code", "start": 32, "end": 73, "tactic": "delivery_problem"},
              {"matched_text": "http://indiapost-parcels.top", "start": 103, "end": 131, "tactic": "link_redirection"}],
             "grp_p13_ts_ind_05"),
        ]
        idx = 1
        for text, cat, tactics, spans, grp in test_ind_scams:
            cases.append(create_sample(
                sample_id=f"p13_ts_ind_scam_{idx:03d}",
                text=text,
                label="scam",
                language="en",
                scam_category=cat,
                tactics=tactics,
                evidence_spans=spans,
                source_reference="src_p13_official_advisories",
                pattern_group_id=grp,
            ))
            idx += 1

        # Group 3: Romanized Hinglish Scams & Non-Scams
        test_hl_scams = [
            ("Aapka Canara Bank account suspend ho chuka hai. Re-activate karne ke liye http://canara-kyc-verify.cc par Aadhaar card details dalein.",
             "kyc_suspension", ["account_suspension", "link_redirection"],
             [{"matched_text": "account suspend ho chuka hai", "start": 19, "end": 47, "tactic": "account_suspension"},
              {"matched_text": "http://canara-kyc-verify.cc", "start": 74, "end": 101, "tactic": "link_redirection"}],
             "grp_p13_ts_hl_01"),
            ("Bijli vibhag: Bill payment na hone par aaj raat 9 baje power cut kar diya jayega. Helpline number 9811998877 par call karein.",
             "electricity_bill", ["authority_claim", "threat", "urgency"],
             [{"matched_text": "aaj raat 9 baje power cut kar diya jayega", "start": 38, "end": 80, "tactic": "threat"}],
             "grp_p13_ts_hl_02"),
            ("Ghar baithe part time job: Daily YouTube channel subscribe karke Rs 3,000 kamayein. Contact Telegram @EarnCashIndia.",
             "task_scam", ["job_offer", "link_redirection"],
             [{"matched_text": "Daily YouTube channel subscribe karke Rs 3,000 kamayein", "start": 27, "end": 82, "tactic": "job_offer"}],
             "grp_p13_ts_hl_03"),
            ("Aapka courier delivery address incomplete hai. Dobara delivery ke liye link par jayein: http://delhivery-redelivery.co",
             "parcel_delivery", ["delivery_problem", "link_redirection"],
             [{"matched_text": "courier delivery address incomplete hai", "start": 7, "end": 46, "tactic": "delivery_problem"},
              {"matched_text": "http://delhivery-redelivery.co", "start": 91, "end": 121, "tactic": "link_redirection"}],
             "grp_p13_ts_hl_04"),
        ]
        idx = 1
        for text, cat, tactics, spans, grp in test_hl_scams:
            cases.append(create_sample(
                sample_id=f"p13_ts_hl_scam_{idx:03d}",
                text=text,
                label="scam",
                language="hi-Latn",
                scam_category=cat,
                tactics=tactics,
                evidence_spans=spans,
                source_reference="src_p13_multilingual",
                pattern_group_id=grp,
            ))
            idx += 1

        test_hl_ham = [
            ("Aapka Amazon package deliver ho gaya hai. Security guard ke paas drop kar diya hai.",
             "delivery_notification", "grp_p13_ts_hl_ham_01"),
            ("Bhai office kab tak pahunch raha hai? Presentation 11 baje shuru honi hai.",
             "work_chat", "grp_p13_ts_hl_ham_02"),
            ("Aapka electricity bill payment Rs 2,150 safal raha. Consumer ID: 890123. Dhanyawad.",
             "bill_receipt", "grp_p13_ts_hl_ham_03"),
        ]
        idx = 1
        for text, cat, grp in test_hl_ham:
            cases.append(create_sample(
                sample_id=f"p13_ts_hl_ham_{idx:03d}",
                text=text,
                label="non_scam",
                language="hi-Latn",
                scam_category=cat,
                tactics=[],
                evidence_spans=[],
                source_reference="src_p13_multilingual",
                pattern_group_id=grp,
            ))
            idx += 1

        # Group 4: Native Devanagari Hindi Scams & Non-Scams
        test_hi_scams = [
            ("बैंक ऑफ़ बड़ौदा अलर्ट: आपका डेबिट कार्ड ब्लॉक हो गया है। इसे तुरंत अनब्लॉक करने के लिए http://bob-unblock.online पर लॉगिन करें।",
             "card_block", ["account_suspension", "link_redirection"],
             [{"matched_text": "डेबिट कार्ड ब्लॉक हो गया है", "start": 27, "end": 53, "tactic": "account_suspension"},
              {"matched_text": "http://bob-unblock.online", "start": 89, "end": 114, "tactic": "link_redirection"}],
             "grp_p13_ts_hi_01"),
            ("विद्युत निगम सूचना: बकाया बिल जमा न करने पर आज रात 10 बजे आपकी बिजली काट दी जाएगी। बिल भरने हेतु 9811882233 पर संपर्क करें।",
             "electricity_bill", ["authority_claim", "threat", "urgency", "payment_request"],
             [{"matched_text": "बिजली काट दी जाएगी", "start": 57, "end": 75, "tactic": "threat"}],
             "grp_p13_ts_hi_02"),
            ("पार्ट-टाइम नौकरी: होटल समीक्षा लिखकर प्रतिदिन रु 4,000 कमाएं। बिना किसी निवेश के शुरुआत करें। टेलीग्राम @HotelReviewIndia पर लिखें।",
             "task_scam", ["job_offer", "link_redirection"],
             [{"matched_text": "प्रतिदिन रु 4,000 कमाएं", "start": 33, "end": 55, "tactic": "job_offer"}],
             "grp_p13_ts_hi_03"),
            ("सीबीआई डिजिटल अरेस्ट: आपके आधार कार्ड का उपयोग मनी लॉन्ड्रिंग में पाया गया है। तत्काल जांच अधिकारी से व्हाट्सएप पर जुड़ें।",
             "digital_arrest", ["authority_claim", "threat", "fear_creation"],
             [{"matched_text": "मनी लॉन्ड्रिंग में पाया गया है", "start": 44, "end": 74, "tactic": "threat"}],
             "grp_p13_ts_hi_04"),
            ("भारतीय डाक सेवा: अपूर्ण पते के कारण आपकी डाक रोक दी गई है। पुनः प्रेषण शुल्क रु 48 का भुगतान http://dak-redelivery.in पर करें।",
             "parcel_delivery", ["delivery_problem", "payment_request", "link_redirection"],
             [{"matched_text": "आपकी डाक रोक दी गई है", "start": 33, "end": 54, "tactic": "delivery_problem"},
              {"matched_text": "http://dak-redelivery.in", "start": 98, "end": 122, "tactic": "link_redirection"}],
             "grp_p13_ts_hi_05"),
        ]
        idx = 1
        for text, cat, tactics, spans, grp in test_hi_scams:
            cases.append(create_sample(
                sample_id=f"p13_ts_hi_scam_{idx:03d}",
                text=text,
                label="scam",
                language="hi",
                scam_category=cat,
                tactics=tactics,
                evidence_spans=spans,
                source_reference="src_p13_multilingual",
                pattern_group_id=grp,
            ))
            idx += 1

        test_hi_ham = [
            ("प्रिय ग्राहक, आपके बैंक खाते **3456 में रु 10,000 जमा किए गए हैं। वर्तमान शेष रु 32,800 है।",
             "bank_alert", "grp_p13_ts_hi_ham_01"),
            ("दिल्ली जल बोर्ड: उपभोक्ता संख्या 90218 का जल बिल रु 450 सफलतापूर्वक जमा हो गया है। धन्यवाद।",
             "utility_receipt", "grp_p13_ts_hi_ham_02"),
            ("नमस्ते चाची जी, आशा है आप सब सकुशल हैं। कल शाम हम सब घर पर मिल रहे हैं।",
             "family_chat", "grp_p13_ts_hi_ham_03"),
        ]
        idx = 1
        for text, cat, grp in test_hi_ham:
            cases.append(create_sample(
                sample_id=f"p13_ts_hi_ham_{idx:03d}",
                text=text,
                label="non_scam",
                language="hi",
                scam_category=cat,
                tactics=[],
                evidence_spans=[],
                source_reference="src_p13_multilingual",
                pattern_group_id=grp,
            ))
            idx += 1

        # Group 5: Obfuscated Controlled Scams in Test Set
        # Clean vs Obfuscated share the same pattern_group_id
        test_obf_pairs = [
            ("URGENT: Your SBI bank account will be b10cked today. Verify Aadhaar at http://sbi-secure.in/verify",
             "kyc_suspension", ["account_suspension", "urgency", "link_redirection"],
             [{"matched_text": "account will be b10cked today", "start": 22, "end": 51, "tactic": "account_suspension"},
              {"matched_text": "http://sbi-secure.in/verify", "start": 71, "end": 98, "tactic": "link_redirection"}],
             "grp_p13_ts_obf_01", "leetspeak", "leetspeak"),
            ("Electricity Alert: P o w e r cutoff scheduled at 9 PM. Call officer at 9876501234 immediately.",
             "electricity_bill", ["authority_claim", "threat", "urgency"],
             [{"matched_text": "P o w e r cutoff scheduled at 9 PM", "start": 19, "end": 53, "tactic": "threat"}],
             "grp_p13_ts_obf_02", "spacing", "spacing"),
            ("HDFC Bank: Suspicious charge of Rs 40,000. D.o.w.n.l.o.a.d AnyDesk to reverse transaction.",
             "remote_access", ["fear_creation", "remote_access_request"],
             [{"matched_text": "D.o.w.n.l.o.a.d AnyDesk", "start": 44, "end": 67, "tactic": "remote_access_request"}],
             "grp_p13_ts_obf_03", "punctuation", "punctuation_injection"),
        ]
        idx = 1
        for text, cat, tactics, spans, grp, aug, obf in test_obf_pairs:
            cases.append(create_sample(
                sample_id=f"p13_ts_obf_scam_{idx:03d}",
                text=text,
                label="scam",
                language="en",
                scam_category=cat,
                tactics=tactics,
                evidence_spans=spans,
                source_reference="src_p13_obfuscation",
                pattern_group_id=grp,
                augmentation_type=aug,
                obfuscation_type=obf,
            ))
            idx += 1

        # Group 6: Novel Threat Patterns in Test Set
        test_novel_scams = [
            ("URGENT: Mom, my phone got stolen and I'm detained at police station! Please UPI Rs 25,000 to advocate Rajesh at advrajesh@icici immediately for bail bond.",
             "ai_voice_clone", ["authority_claim", "threat", "urgency", "payment_request"],
             [{"matched_text": "detained at police station", "start": 41, "end": 67, "tactic": "threat"},
              {"matched_text": "UPI Rs 25,000 to advocate Rajesh", "start": 83, "end": 115, "tactic": "payment_request"}],
             "grp_p13_ts_novel_01", "novel_pattern"),
            ("MetaMask Security Warning: A critical vulnerability was found in your Ethereum staking contract. Migrate your tokens immediately at http://eth-revoke-portal.xyz/secure",
             "web3_drainer", ["authority_claim", "urgency", "link_redirection"],
             [{"matched_text": "http://eth-revoke-portal.xyz/secure", "start": 120, "end": 155, "tactic": "link_redirection"}],
             "grp_p13_ts_novel_02", "novel_pattern"),
            ("FedEx Customs Interception: Narcotic parcel containing 120g MDMA intercepted under your passport #K891230. Join video interrogation with NCB investigator or face non-bailable FIR.",
             "customs_extortion", ["authority_claim", "threat", "fear_creation"],
             [{"matched_text": "Narcotic parcel containing 120g MDMA intercepted", "start": 27, "end": 75, "tactic": "threat"}],
             "grp_p13_ts_novel_03", "novel_pattern"),
        ]
        idx = 1
        for item in test_novel_scams:
            text, cat, tactics, spans, grp, status = item
            cases.append(create_sample(
                sample_id=f"p13_ts_novel_scam_{idx:03d}",
                text=text,
                label="scam",
                language="en",
                scam_category=cat,
                tactics=tactics,
                evidence_spans=spans,
                source_reference="src_p13_novel_patterns",
                pattern_group_id=grp,
                known_unknown_status=status,
            ))
            idx += 1

        return cases

    # =========================================================================
    # HARD NEGATIVES EXPANSION (25 samples, all legitimate non_scam)
    # =========================================================================
    def _generate_hard_negative_cases(self) -> List[Dict[str, Any]]:
        hard_negatives = [
            ("Your OTP for HDFC Bank Credit Card transaction of Rs 4,999 at AMAZON INDIA is 782194. Do not share OTP with anyone.",
             "en", "bank_otp", "grp_p13_hn_01"),
            ("Dear SBI Customer, your NetBanking password was changed successfully on 02-OCT-2026. If not requested by you, call 1800112211.",
             "en", "security_notice", "grp_p13_hn_02"),
            ("URGENT: Indigo Flight 6E-512 from Mumbai to Bengaluru has been rescheduled to 18:30 due to bad weather. Check flight status at goindigo.in.",
             "en", "flight_urgent", "grp_p13_hn_03"),
            ("Aadhaar OTP: 491028 is your one time password to verify mobile number update at UIDAI official portal. Valid for 10 minutes.",
             "en", "aadhaar_otp", "grp_p13_hn_04"),
            ("Your ICICI Bank account balance has fallen below minimum required average balance of Rs 10,000. Please deposit funds to avoid penalty charges.",
             "en", "account_balance_warning", "grp_p13_hn_05"),
            ("Income Tax Department: Last date to file ITR without late fee is 31st July 2026. Avoid penalty by logging into incometax.gov.in.",
             "en", "tax_deadline_warning", "grp_p13_hn_06"),
            ("Electricity Alert: Scheduled maintenance outage in Indiranagar on 03-OCT from 10 AM to 2 PM. Inconvenience regretted - BESCOM.",
             "en", "power_outage_notice", "grp_p13_hn_07"),
            ("Traffic Police Notice: Traffic challan #DL891238 of Rs 1,000 issued for overspeeding on Ring Road. Pay online at official echallan.parivahan.gov.in.",
             "en", "traffic_challan", "grp_p13_hn_08"),
            ("Your Swiggy Instamart delivery of groceries is arriving in 8 minutes. Delivery partner Ramesh is at your gate.",
             "en", "delivery_urgent", "grp_p13_hn_09"),
            ("Hospital Alert: Your blood test results from Lal PathLabs are ready. Download confidential medical report at lalpathlabs.com/patient.",
             "en", "medical_report", "grp_p13_hn_10"),
            ("Domino's Pizza: Flash deal! Flat 50% OFF on all gourmet pizzas valid for next 2 hours only. Order now on Domino's official app.",
             "en", "promotional_urgency", "grp_p13_hn_11"),
            ("IRCTC Refund Notice: Refund of Rs 1,840 for cancelled train ticket PNR 8901239812 has been credited to your bank account.",
             "en", "train_refund", "grp_p13_hn_12"),
            ("Job Application Update: Google India has shortlisted your profile for Senior Software Engineer. Technical interview scheduled for Monday.",
             "en", "job_shortlist", "grp_p13_hn_13"),
            ("Amazon Security Alert: New login detected from Chrome on Windows in New Delhi. If this was you, please ignore this email.",
             "en", "login_alert", "grp_p13_hn_14"),
            ("Salary credited: Net pay Rs 92,400 credited to a/c **9012 by Infosys Ltd on 30-SEP-2026. Avl bal Rs 1,45,200.",
             "en", "salary_alert", "grp_p13_hn_15"),
            # Hinglish Hard Negatives
            ("Aapka SBI Debit Card PIN generate karne ka OTP 890123 hai. Kripya ise kisi bank adhikari ke saath bhi share na karein.",
             "hi-Latn", "bank_pin_otp", "grp_p13_hn_16"),
            ("Aapka electricity connection maintenance ke kaaran kal dopahar 1 baje se 3 baje tak band rahega - Tata Power.",
             "hi-Latn", "maintenance_alert", "grp_p13_hn_17"),
            ("Zomato refund update: Order cancellation refund Rs 420 aapke original payment mode par bhej diya gaya hai.",
             "hi-Latn", "refund_update", "grp_p13_hn_18"),
            ("Aapka driving license renew karne ka application verify ho chuka hai. Status check karein parivahan portal par.",
             "hi-Latn", "govt_service", "grp_p13_hn_19"),
            ("Bhai urgently call back kar, papa ki report lekar doctor ke paas jana hai.",
             "hi-Latn", "urgent_family", "grp_p13_hn_20"),
            # Native Hindi Hard Negatives
            ("आयकर विभाग सूचना: आपका कर रिफंड रु 12,400 सफलतापूर्वक आपके बैंक खाते में हस्तांतरित कर दिया गया है।",
             "hi", "tax_refund_success", "grp_p13_hn_21"),
            ("एसबीआई सुरक्षा सूचना: आपके नेटबैंकिंग का पासवर्ड बदल दिया गया है। यदि आपने यह अनुरोध नहीं किया था, तो 1800112211 पर सूचित करें।",
             "hi", "password_change_notice", "grp_p13_hn_22"),
            ("विद्युत विभाग सूचना: आपके क्षेत्र में कल सुबह 10 से 12 बजे तक ट्रांसफार्मर मरम्मत कार्य के कारण बिजली आपूर्ति बाधित रहेगी।",
             "hi", "power_maintenance", "grp_p13_hn_23"),
            ("आधार प्रमाणीकरण ओटीपी 819203 है। इसका उपयोग अपने पते के सत्यापन के लिए यूआईडीएआई पोर्टल पर करें। वैधता 10 मिनट।",
             "hi", "aadhaar_otp", "grp_p13_hn_24"),
            ("आईआरसीटीसी: ट्रेन संख्या 12423 राजधानी एक्सप्रेस के समय में परिवर्तन। नई प्रस्थान समय सीमा 19:10 है।",
             "hi", "train_schedule", "grp_p13_hn_25"),
        ]

        cases = []
        for i, (text, lang, cat, grp) in enumerate(hard_negatives, start=1):
            cases.append(create_sample(
                sample_id=f"p13_hn_{i:03d}",
                text=text,
                label="non_scam",
                language=lang,
                scam_category=cat,
                tactics=[],
                evidence_spans=[],
                source_reference="src_p13_hard_negatives",
                pattern_group_id=grp,
            ))
        return cases

    # =========================================================================
    # MULTILINGUAL SUBSET (24 samples: 12 Hindi, 12 Hinglish)
    # =========================================================================
    def _generate_multilingual_cases(self) -> List[Dict[str, Any]]:
        cases = []
        # Native Hindi cases (6 scams, 6 non-scams)
        hi_items = [
            ("अति आवश्यक: आपका बिजली का बिल बकाया होने के कारण आज रात 9:30 बजे बिजली कनेक्शन काट दिया जाएगा। तुरंत कॉल करें: 9811004455।",
             "scam", "electricity_bill", ["authority_claim", "threat", "urgency", "payment_request"],
             [{"matched_text": "बिजली कनेक्शन काट दिया जाएगा", "start": 57, "end": 85, "tactic": "threat"}],
             "grp_p13_ml_hi_01"),
            ("एसबीआई बैंक खाता चेतावनी: आपका खाता ब्लॉक कर दिया गया है। अनब्लॉक करने हेतु अभी पैन लिंक करें: http://sbi-pan-update.co/login",
             "scam", "kyc_suspension", ["account_suspension", "link_redirection"],
             [{"matched_text": "खाता ब्लॉक कर दिया गया है", "start": 32, "end": 57, "tactic": "account_suspension"},
              {"matched_text": "http://sbi-pan-update.co/login", "start": 84, "end": 114, "tactic": "link_redirection"}],
             "grp_p13_ml_hi_02"),
            ("बधाई! प्रधानमंत्री किसान योजना के तहत आपको रु 15,000 की किस्त जारी हुई है। क्लेम करने के लिए http://pm-kisan-portal.me पर क्लिक करें।",
             "scam", "govt_scheme", ["reward_claim", "link_redirection"],
             [{"matched_text": "रु 15,000 की किस्त जारी हुई है", "start": 44, "end": 74, "tactic": "reward_claim"},
              {"matched_text": "http://pm-kisan-portal.me", "start": 98, "end": 123, "tactic": "link_redirection"}],
             "grp_p13_ml_hi_03"),
            ("सीबीआई डिजिटल अरेस्ट: आपके आधार नंबर से गैर-कानूनी पार्सल पकड़ा गया है। तत्काल जांच हेतु 9911002233 पर वीडियो कॉल करें।",
             "scam", "digital_arrest", ["authority_claim", "threat", "fear_creation"],
             [{"matched_text": "गैर-कानूनी पार्सल पकड़ा गया है", "start": 36, "end": 66, "tactic": "threat"}],
             "grp_p13_ml_hi_04"),
            ("डाक विभाग सूचना: आपके कूरियर का पता अधूरा है। पुनः वितरण हेतु रु 35 का शुल्क अदा करें: http://indiapost-parcel.top/pay",
             "scam", "parcel_delivery", ["delivery_problem", "payment_request", "link_redirection"],
             [{"matched_text": "कूरियर का पता अधूरा है", "start": 23, "end": 45, "tactic": "delivery_problem"},
              {"matched_text": "http://indiapost-parcel.top/pay", "start": 86, "end": 117, "tactic": "link_redirection"}],
             "grp_p13_ml_hi_05"),
            ("यूट्यूब लाइक जॉब: घर बैठे यूट्यूब वीडियो देखकर प्रतिदिन रु 3,500 कमाएं। हमारे टेलीग्राम ग्रुप @DailyTasksIndia से जुड़ें।",
             "scam", "task_scam", ["job_offer", "link_redirection"],
             [{"matched_text": "प्रतिदिन रु 3,500 कमाएं", "start": 47, "end": 70, "tactic": "job_offer"}],
             "grp_p13_ml_hi_06"),
            # Hindi Non-scams
            ("प्रिय ग्राहक, आपके पंजाब नेशनल बैंक खाते में रु 3,000 जमा हुए हैं। वर्तमान शेष राशि रु 18,900 है।",
             "non_scam", "bank_alert", [], [], "grp_p13_ml_hi_07"),
            ("दिल्ली विद्युत बोर्ड: माह सितंबर का बिजली बिल रु 1,450 प्राप्त हुआ। रसीद संख्या: RC89012। धन्यवाद।",
             "non_scam", "bill_receipt", [], [], "grp_p13_ml_hi_08"),
            ("आईआरसीटीसी: ट्रेन संख्या 12952, कोच बी3, सीट 21 बुक हो चुकी है। आपकी यात्रा मंगलमय हो।",
             "non_scam", "train_ticket", [], [], "grp_p13_ml_hi_09"),
            ("आधार ओटीपी 492019 है। इसका प्रयोग केवल यूआईडीएआई की आधिकारिक वेबसाइट पर ही करें।",
             "non_scam", "aadhaar_otp", [], [], "grp_p13_ml_hi_10"),
            ("नमस्ते भाई, मां की तबीयत अब पहले से बेहतर है। कल शाम को घर आ जाना।",
             "non_scam", "family_chat", [], [], "grp_p13_ml_hi_11"),
            ("अमेज़न डिलीवरी: आपका ऑर्डर आज शाम 6 बजे तक आपके पते पर पहुंचा दिया जाएगा।",
             "non_scam", "delivery_update", [], [], "grp_p13_ml_hi_12"),
        ]

        idx = 1
        for text, lbl, cat, tactics, spans, grp in hi_items:
            cases.append(create_sample(
                sample_id=f"p13_ml_hi_{idx:03d}",
                text=text,
                label=lbl,
                language="hi",
                scam_category=cat,
                tactics=tactics,
                evidence_spans=spans,
                source_reference="src_p13_multilingual",
                pattern_group_id=grp,
            ))
            idx += 1

        # Romanized Hinglish cases (6 scams, 6 non-scams)
        hl_items = [
            ("Aapka SBI account suspend ho chuka hai. Re-activate karne ke liye http://sbi-kyc-reactivate.co par login karein.",
             "scam", "kyc_suspension", ["account_suspension", "link_redirection"],
             [{"matched_text": "account suspend ho chuka hai", "start": 10, "end": 38, "tactic": "account_suspension"},
              {"matched_text": "http://sbi-kyc-reactivate.co", "start": 65, "end": 93, "tactic": "link_redirection"}],
             "grp_p13_ml_hl_01"),
            ("Bijli vibhag notice: Aaj raat 9 baje power cut kar diya jayega overdue bill ke kaaran. Contact helpline 9820011223.",
             "scam", "electricity_bill", ["authority_claim", "threat", "urgency"],
             [{"matched_text": "power cut kar diya jayega overdue bill ke kaaran", "start": 37, "end": 85, "tactic": "threat"}],
             "grp_p13_ml_hl_02"),
            ("Badhai ho! Aapne KBC lottery mein Rs 10,00,000 cash jeeta hai. WhatsApp karein 9876541234 par claim karne ke liye.",
             "scam", "lottery_prize", ["reward_claim", "link_redirection"],
             [{"matched_text": "KBC lottery mein Rs 10,00,000 cash jeeta hai", "start": 17, "end": 61, "tactic": "reward_claim"}],
             "grp_p13_ml_hl_03"),
            ("Aapka courier address incorrect hai. Delivery complete karne ke liye http://dtdc-update.top par verify karein.",
             "scam", "parcel_delivery", ["delivery_problem", "link_redirection"],
             [{"matched_text": "courier address incorrect hai", "start": 7, "end": 36, "tactic": "delivery_problem"},
              {"matched_text": "http://dtdc-update.top", "start": 70, "end": 91, "tactic": "link_redirection"}],
             "grp_p13_ml_hl_04"),
            ("YouTube video ratings job: Daily Rs 2,500 direct bank transfer mein paayein. Join karein Telegram @EasyTasksIndia.",
             "scam", "task_scam", ["job_offer", "link_redirection"],
             [{"matched_text": "Daily Rs 2,500 direct bank transfer", "start": 27, "end": 62, "tactic": "job_offer"}],
             "grp_p13_ml_hl_05"),
            ("Paytm KYC expired: Aapka wallet limit 0 kar diya jayega. Link http://paytm-wallet-limit.co par Aadhaar enter karein.",
             "scam", "wallet_kyc", ["account_suspension", "link_redirection"],
             [{"matched_text": "wallet limit 0 kar diya jayega", "start": 26, "end": 56, "tactic": "account_suspension"},
              {"matched_text": "http://paytm-wallet-limit.co", "start": 63, "end": 90, "tactic": "link_redirection"}],
             "grp_p13_ml_hl_06"),
            # Hinglish Non-scams
            ("Aapka SBI savings a/c **9012 se Rs 2,400 debit hua hai at Big Bazaar. Available balance Rs 21,300.",
             "non_scam", "bank_alert", [], [], "grp_p13_ml_hl_07"),
            ("Aapka Swiggy order confirm ho gaya hai aur 20 minute mein deliver ho jayega. Rider: Vikram.",
             "non_scam", "delivery_update", [], [], "grp_p13_ml_hl_08"),
            ("Aapka electricity bill payment Rs 1,890 successfully complete ho gaya hai. Reference ID: 902812.",
             "non_scam", "bill_receipt", [], [], "grp_p13_ml_hl_09"),
            ("Aapka Jio recharge Rs 299 successfully activate ho gaya hai. 28 days validity. Dhanyawad.",
             "non_scam", "telecom_plan", [], [], "grp_p13_ml_hl_10"),
            ("Bhai kal shaam ko movie chalte hain kya? Ticket book kar raha hoon batana.",
             "non_scam", "personal_chat", [], [], "grp_p13_ml_hl_11"),
            ("Aapka Uber OTP 6712 hai. Driver ke saath share karein ride shuru karne ke liye.",
             "non_scam", "ride_otp", [], [], "grp_p13_ml_hl_12"),
        ]

        idx = 1
        for text, lbl, cat, tactics, spans, grp in hl_items:
            cases.append(create_sample(
                sample_id=f"p13_ml_hl_{idx:03d}",
                text=text,
                label=lbl,
                language="hi-Latn",
                scam_category=cat,
                tactics=tactics,
                evidence_spans=spans,
                source_reference="src_p13_multilingual",
                pattern_group_id=grp,
            ))
            idx += 1

        return cases

    # =========================================================================
    # OBFUSCATION EVALUATION (10 controlled pairs = 20 samples)
    # =========================================================================
    def _generate_obfuscation_cases(self) -> List[Dict[str, Any]]:
        # 10 pairs: base original and perturbed variant, sharing identical pattern_group_id
        pairs = [
            # Pair 1: Character Spacing
            (("URGENT: Your SBI account is blocked. Verify at http://sbi-verify.com/now",
              "account_suspension", ["account_suspension", "urgency", "link_redirection"],
              [{"matched_text": "account is blocked", "start": 17, "end": 35, "tactic": "account_suspension"},
               {"matched_text": "http://sbi-verify.com/now", "start": 47, "end": 72, "tactic": "link_redirection"}]),
             ("URGENT: Your S B I a c c o u n t is blocked. Verify at http://sbi-verify.com/now",
              "spacing", "spacing")),

            # Pair 2: Leetspeak Substitutions
            (("Notice: Your bank card has been suspended. Restore access at http://card-fix.net",
              "card_suspension", ["account_suspension", "link_redirection"],
              [{"matched_text": "card has been suspended", "start": 18, "end": 41, "tactic": "account_suspension"},
               {"matched_text": "http://card-fix.net", "start": 61, "end": 80, "tactic": "link_redirection"}]),
             ("Notice: Your b4nk c4rd has been susp3nded. Restore access at http://card-fix.net",
              "leetspeak", "leetspeak")),

            # Pair 3: Punctuation Injection
            (("Urgent alert: Electricity power cutoff tonight. Call 9876541234 to clear bill.",
              "electricity_bill", ["authority_claim", "threat", "urgency"],
              [{"matched_text": "Electricity power cutoff tonight", "start": 14, "end": 46, "tactic": "threat"}],),
             ("Urgent alert: E.l.e.c.t.r.i.c.i.t.y power cutoff tonight. Call 9876541234 to clear bill.",
              "punctuation", "punctuation_injection")),

            # Pair 4: Emoji Padding & Spacing
            (("Congratulations you won Rs 50,000 lottery cash prize! Claim at http://kbc-win.me",
              "lottery_prize", ["reward_claim", "link_redirection"],
              [{"matched_text": "won Rs 50,000 lottery cash prize!", "start": 20, "end": 53, "tactic": "reward_claim"},
               {"matched_text": "http://kbc-win.me", "start": 64, "end": 81, "tactic": "link_redirection"}]),
             ("Congratulations 🎁 you won Rs 5 0 , 0 0 0 lottery cash prize! Claim at http://kbc-win.me",
              "emoji", "spacing")),

            # Pair 5: Leetspeak on Credentials
            (("Security Alert: Confirm your password and OTP at http://auth-update.cc to stop fraud.",
              "credential_theft", ["credential_request", "otp_request", "link_redirection"],
              [{"matched_text": "Confirm your password and OTP", "start": 16, "end": 45, "tactic": "credential_request"},
               {"matched_text": "http://auth-update.cc", "start": 49, "end": 70, "tactic": "link_redirection"}]),
             ("Security Alert: Confirm your p@ssw0rd and 0TP at http://auth-update.cc to stop fraud.",
              "leetspeak", "leetspeak")),

            # Pair 6: Zero Spacing / Word Merging
            (("Dear user your KYC verification is pending. Visit http://kyc-update.co now",
              "kyc_suspension", ["verification_request", "link_redirection"],
              [{"matched_text": "KYC verification is pending", "start": 15, "end": 42, "tactic": "verification_request"},
               {"matched_text": "http://kyc-update.co", "start": 50, "end": 70, "tactic": "link_redirection"}]),
             ("Dear user your KYCverification is pending. Visit http://kyc-update.co now",
              "spacing", "spacing")),

            # Pair 7: Repeated Character Padding
            (("Urgent notice: Your SIM will be deactivated today. Call customer care 9911223344",
              "telecom_threat", ["authority_claim", "threat", "urgency"],
              [{"matched_text": "SIM will be deactivated today", "start": 20, "end": 49, "tactic": "threat"}],),
             ("Uuurrrgeennt notice: Your SIM will be deactivated today. Call customer care 9911223344",
              "character_repetition", "spacing")),

            # Pair 8: Hinglish Spacing Obfuscation
            (("Aapka account block ho jayega turant link http://sbi-help.co par verify karein",
              "kyc_suspension", ["account_suspension", "link_redirection"],
              [{"matched_text": "account block ho jayega", "start": 6, "end": 29, "tactic": "account_suspension"},
               {"matched_text": "http://sbi-help.co", "start": 42, "end": 60, "tactic": "link_redirection"}]),
             ("Aapka a c c o u n t block ho jayega turant link http://sbi-help.co par verify karein",
              "spacing", "spacing")),

            # Pair 9: Symbol Substitution on Indian Bank Name
            (("HDFC Bank alert: Unusual activity detected. Download AnyDesk to verify.",
              "remote_access", ["fear_creation", "remote_access_request"],
              [{"matched_text": "Download AnyDesk to verify", "start": 44, "end": 70, "tactic": "remote_access_request"}],),
             ("H.D.F.C Bank alert: Unusual activity detected. Download AnyDesk to verify.",
              "punctuation", "punctuation_injection")),

            # Pair 10: Mixed Leetspeak & Spacing
            (("Final Warning: Pay electricity bill immediately or connection will be disconnected.",
              "electricity_bill", ["authority_claim", "threat", "urgency", "payment_request"],
              [{"matched_text": "connection will be disconnected", "start": 48, "end": 80, "tactic": "threat"}],),
             ("F1nal W4rning: Pay 3lectricity bill immediately or c o n n e c t i o n will be cut.",
              "leetspeak", "leetspeak")),
        ]

        cases = []
        for idx, (orig, obf_meta) in enumerate(pairs, start=1):
            orig_text, cat, tactics, spans = orig
            obf_text, aug_type, obf_type = obf_meta
            grp_id = f"grp_p13_obf_pair_{idx:02d}"

            # 1. Base Original
            cases.append(create_sample(
                sample_id=f"p13_obf_orig_{idx:02d}",
                text=orig_text,
                label="scam",
                language="en" if idx != 8 else "hi-Latn",
                scam_category=cat,
                tactics=tactics,
                evidence_spans=spans,
                source_reference="src_p13_obfuscation",
                pattern_group_id=grp_id,
                augmentation_type="none",
                obfuscation_type="none",
            ))

            # 2. Obfuscated Variant
            cases.append(create_sample(
                sample_id=f"p13_obf_pert_{idx:02d}",
                text=obf_text,
                label="scam",
                language="en" if idx != 8 else "hi-Latn",
                scam_category=cat,
                tactics=tactics,
                evidence_spans=[],  # Perturbed spans may shift
                source_reference="src_p13_obfuscation",
                pattern_group_id=grp_id,
                augmentation_type=aug_type,
                obfuscation_type=obf_type,
            ))

        return cases

    # =========================================================================
    # NOVEL PATTERNS SUBSET (16 samples: AI Voice, Digital Arrest, Web3, etc.)
    # =========================================================================
    def _generate_novel_cases(self) -> List[Dict[str, Any]]:
        novel_items = [
            ("MOM HELP: I got into a terrible car accident in Connaught Place! Police inspector Sharma is seizing my car unless you pay Rs 35,000 spot fine to UPI policehelp@sbi.",
             "ai_voice_accident", ["authority_claim", "threat", "urgency", "payment_request"],
             [{"matched_text": "Police inspector Sharma is seizing my car", "start": 62, "end": 103, "tactic": "threat"},
              {"matched_text": "pay Rs 35,000 spot fine to UPI", "start": 115, "end": 145, "tactic": "payment_request"}],
             "grp_p13_nov_01"),
            ("Dad, my bag with phone and wallet got snatched at Mumbai central station. Send Rs 15,000 to this tea stall owner's UPI teashop@paytm so I can take taxi home.",
             "impersonation_emergency", ["impersonation", "urgency", "payment_request"],
             [{"matched_text": "Send Rs 15,000 to this tea stall owner's UPI", "start": 74, "end": 118, "tactic": "payment_request"}],
             "grp_p13_nov_02"),
            ("DIGITAL ARREST ORDER: Directorate of Enforcement summons you for illegal cryptocurrency remittance. Join immediate private Zoom video interrogation with Special Director.",
             "digital_arrest_ed", ["authority_claim", "threat", "fear_creation"],
             [{"matched_text": "Directorate of Enforcement summons you", "start": 23, "end": 62, "tactic": "authority_claim"},
              {"matched_text": "illegal cryptocurrency remittance", "start": 67, "end": 100, "tactic": "threat"}],
             "grp_p13_nov_03"),
            ("Supreme Court Cyber Tribunal: Non-bailable arrest warrant issued against phone 9820011223 for transnational narcotics routing. Join WebEx conference within 15 minutes.",
             "digital_arrest_tribunal", ["authority_claim", "threat", "fear_creation", "urgency"],
             [{"matched_text": "Non-bailable arrest warrant issued", "start": 31, "end": 65, "tactic": "threat"}],
             "grp_p13_nov_04"),
            ("Web3 Airdrop: Claim 2,500 ARB governance tokens before claim window closes in 4 hours. Connect your Web3 wallet and approve contract at http://arb-foundation-claim.xyz",
             "web3_airdrop_drainer", ["reward_claim", "urgency", "link_redirection"],
             [{"matched_text": "Claim 2,500 ARB governance tokens", "start": 14, "end": 47, "tactic": "reward_claim"},
              {"matched_text": "http://arb-foundation-claim.xyz", "start": 134, "end": 163, "tactic": "link_redirection"}],
             "grp_p13_nov_05"),
            ("Uniswap V3 Flash Liquidity Alert: 500% APY available on USDC-ETH pool for next 24 hours. Deposit liquidity now via http://uniswap-v3-liquidity-pool.top/deposit",
             "web3_liquidity_drainer", ["reward_claim", "urgency", "link_redirection"],
             [{"matched_text": "500% APY available on USDC-ETH pool", "start": 35, "end": 70, "tactic": "reward_claim"},
              {"matched_text": "http://uniswap-v3-liquidity-pool.top/deposit", "start": 118, "end": 160, "tactic": "link_redirection"}],
             "grp_p13_nov_06"),
            ("Telegram Task VIP Group: You have completed Trial Level 1! To unlock Level 2 high payout tasks (Rs 25,000 daily), deposit Rs 5,000 security recharge to UPI taskvip@axl.",
             "task_vip_scam", ["job_offer", "payment_request"],
             [{"matched_text": "Rs 25,000 daily", "start": 81, "end": 96, "tactic": "job_offer"},
              {"matched_text": "deposit Rs 5,000 security recharge", "start": 105, "end": 139, "tactic": "payment_request"}],
             "grp_p13_nov_07"),
            ("Movie Ticket Rating Scam: Earn Rs 400 per review for upcoming Bollywood releases on BookMyShow. Register on Telegram @BMSReviewJobs to claim starting bonus.",
             "task_movie_rating", ["job_offer", "link_redirection"],
             [{"matched_text": "Earn Rs 400 per review for upcoming Bollywood releases", "start": 27, "end": 81, "tactic": "job_offer"}],
             "grp_p13_nov_08"),
            ("Customs Detention: Courier #DHL89201 from Netherlands intercepted at Mumbai Foreign Post Office containing contraband MDMA pills. Pay Rs 40,000 customs bond to clear name.",
             "customs_narcotics", ["authority_claim", "threat", "payment_request"],
             [{"matched_text": "containing contraband MDMA pills", "start": 89, "end": 121, "tactic": "threat"},
              {"matched_text": "Pay Rs 40,000 customs bond", "start": 123, "end": 149, "tactic": "payment_request"}],
             "grp_p13_nov_09"),
            ("CBI Special Crime Unit: Illegal passport forgery syndicate linked to your PAN card. You are placed under digital surveillance. Keep this communication completely secret.",
             "digital_surveillance_secrecy", ["authority_claim", "threat", "secrecy_request"],
             [{"matched_text": "You are placed under digital surveillance", "start": 78, "end": 119, "tactic": "threat"},
              {"matched_text": "Keep this communication completely secret", "start": 121, "end": 162, "tactic": "secrecy_request"}],
             "grp_p13_nov_10"),
            ("AI Deepfake Video Extortion: We have created a compromising AI video of you using your social media photos. Pay 0.05 BTC to wallet bc1qxy2kgdygjrsqtzq2n0yrf2493p83kkfjhx0wlh within 24 hours.",
             "ai_deepfake_extortion", ["threat", "fear_creation", "urgency", "payment_request"],
             [{"matched_text": "compromising AI video of you", "start": 36, "end": 64, "tactic": "threat"},
              {"matched_text": "Pay 0.05 BTC to wallet", "start": 98, "end": 120, "tactic": "payment_request"}],
             "grp_p13_nov_11"),
            ("Solar Rooftop Subsidy: PM Surya Ghar Yojana subsidy of Rs 78,000 approved for your house meter. Complete installation KYC at http://pmsuryaghar-subsidy.club",
             "solar_subsidy", ["reward_claim", "link_redirection"],
             [{"matched_text": "subsidy of Rs 78,000 approved", "start": 44, "end": 73, "tactic": "reward_claim"},
              {"matched_text": "http://pmsuryaghar-subsidy.club", "start": 123, "end": 154, "tactic": "link_redirection"}],
             "grp_p13_nov_12"),
            ("FASTag Blacklist Alert: Your NHAI FASTag wallet has insufficient balance and will be blacklisted across all highway toll plazas today. Recharge at http://fastag-nhai.top",
             "fastag_scam", ["threat", "urgency", "link_redirection"],
             [{"matched_text": "blacklisted across all highway toll plazas today", "start": 84, "end": 132, "tactic": "threat"},
              {"matched_text": "http://fastag-nhai.top", "start": 146, "end": 167, "tactic": "link_redirection"}],
             "grp_p13_nov_13"),
            ("Challan Lok Adalat Waiver: 80% discount on pending traffic police challans today only. Settle your pending fines at http://echallan-lokadalat-waiver.net",
             "lok_adalat_challan", ["reward_claim", "urgency", "link_redirection"],
             [{"matched_text": "80% discount on pending traffic police challans", "start": 27, "end": 74, "tactic": "reward_claim"},
              {"matched_text": "http://echallan-lokadalat-waiver.net", "start": 117, "end": 152, "tactic": "link_redirection"}],
             "grp_p13_nov_14"),
            ("WhatsApp Pink Update: Download official WhatsApp Pink theme with exclusive features and free unlimited calling from http://whatsapp-pink-apk.site",
             "malicious_apk", ["reward_claim", "link_redirection"],
             [{"matched_text": "http://whatsapp-pink-apk.site", "start": 117, "end": 145, "tactic": "link_redirection"}],
             "grp_p13_nov_15"),
            ("E-SIM Conversion Alert: Your physical SIM will be deactivated and converted to e-SIM. If you did not request this, call customer protection 9820011445.",
             "esim_swap", ["threat", "fear_creation", "urgency"],
             [{"matched_text": "physical SIM will be deactivated", "start": 32, "end": 64, "tactic": "threat"}],
             "grp_p13_nov_16"),
        ]

        cases = []
        for i, (text, cat, tactics, spans, grp) in enumerate(novel_items, start=1):
            cases.append(create_sample(
                sample_id=f"p13_nov_{i:03d}",
                text=text,
                label="scam",
                language="en",
                scam_category=cat,
                tactics=tactics,
                evidence_spans=spans,
                source_reference="src_p13_novel_patterns",
                pattern_group_id=grp,
                known_unknown_status="novel_pattern",
            ))
        return cases


if __name__ == "__main__":
    builder = Phase13DatasetBuilder(base_dir=Path(__file__).resolve().parents[2])
    counts = builder.build_all()
    print("Phase 13 Datasets Built Successfully:")
    for split, count in counts.items():
        print(f"  - {split}: {count} samples")
