"""Phase 18C — Production Deployment Smoke Test Suite (Exact 10 Canonical Scenarios).

Verifies the 10 canonical scenarios required by Phase 18C deployment specifications:
1. Benign message
2. Bank phishing message
3. E-challan-style scam
4. Employment scam
5. Legitimate delivery OTP
6. Suspicious URL only
7. Legitimate institutional URL
8. Obfuscated scam
9. Screenshot scan
10. GenAI unavailable/fallback
"""

import io
import json
from pathlib import Path
import sys
import time

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from PIL import Image

from src.app.schemas import InvestigationInput, InvestigationReport
from src.app.service import InvestigationService


def run_smoke_tests():
    print("=" * 70)
    print("SCAMSHIELD AI — PHASE 18C PRODUCTION DEPLOYMENT SMOKE TESTS")
    print("=" * 70)

    service = InvestigationService()
    service.warmup()
    print("InvestigationService initialized & warmed up successfully.\n")

    results = []

    # -------------------------------------------------------------
    # Case 1 — Benign message
    # -------------------------------------------------------------
    c1_in = InvestigationInput(
        text="Hi Mom, I will be home by 7 PM tonight. Please keep dinner ready.",
        case_id="case_01_benign",
    )
    c1_rep = service.investigate(c1_in)
    r1 = {
        "case_id": 1,
        "name": "Benign message",
        "verdict": c1_rep.assessment.get("status"),
        "evidence_level": c1_rep.assessment.get("evidence_level"),
        "latency_ms": round(c1_rep.timings_ms.get("total_ms", 0.0), 1),
        "passed": c1_rep.assessment.get("status") in ["likely_non_scam", "insufficient_evidence"],
    }
    results.append(r1)
    print(f"Case 1 [Benign message]: Verdict={r1['verdict']} (Pass={r1['passed']})")

    # -------------------------------------------------------------
    # Case 2 — Bank phishing message
    # -------------------------------------------------------------
    c2_in = InvestigationInput(
        text="URGENT: Your SBI bank account will be blocked today due to pending KYC. Click http://sbi-kyc-update.xyz to verify immediately.",
        case_id="case_02_bank_phishing",
    )
    c2_rep = service.investigate(c2_in)
    r2 = {
        "case_id": 2,
        "name": "Bank phishing message",
        "verdict": c2_rep.assessment.get("status"),
        "tactics": c2_rep.detected_tactics,
        "passed": c2_rep.assessment.get("status") == "likely_scam",
    }
    results.append(r2)
    print(f"Case 2 [Bank phishing]: Verdict={r2['verdict']}, Tactics={r2['tactics']} (Pass={r2['passed']})")

    # -------------------------------------------------------------
    # Case 3 — E-challan-style scam
    # -------------------------------------------------------------
    c3_in = InvestigationInput(
        text="Traffic Police Notice: Pending challan of Rs 1500 for DL-8C-AA-1234. Pay within 24h at http://echallan-parivahan-pay.cc to avoid vehicle impound.",
        case_id="case_03_echallan",
    )
    c3_rep = service.investigate(c3_in)
    r3 = {
        "case_id": 3,
        "name": "E-challan-style scam",
        "verdict": c3_rep.assessment.get("status"),
        "tactics": c3_rep.detected_tactics,
        "passed": c3_rep.assessment.get("status") in ["likely_scam", "suspicious", "mixed_signals"],
    }
    results.append(r3)
    print(f"Case 3 [E-challan]: Verdict={r3['verdict']} (Pass={r3['passed']})")

    # -------------------------------------------------------------
    # Case 4 — Employment scam
    # -------------------------------------------------------------
    c4_in = InvestigationInput(
        text="Selected for online part-time job! Earn Rs 5,000 daily by liking YouTube videos. Contact HR on Telegram: https://t.me/GlobalRatingsHR to get paid.",
        case_id="case_04_employment",
    )
    c4_rep = service.investigate(c4_in)
    r4 = {
        "case_id": 4,
        "name": "Employment scam",
        "verdict": c4_rep.assessment.get("status"),
        "passed": c4_rep.assessment.get("status") in ["likely_scam", "suspicious", "mixed_signals"],
    }
    results.append(r4)
    print(f"Case 4 [Employment scam]: Verdict={r4['verdict']} (Pass={r4['passed']})")

    # -------------------------------------------------------------
    # Case 5 — Legitimate delivery OTP
    # -------------------------------------------------------------
    c5_in = InvestigationInput(
        text="Your Amazon delivery agent is out for delivery. Share delivery code 491024 with the driver at the door to receive your package.",
        case_id="case_05_delivery_otp",
    )
    c5_rep = service.investigate(c5_in)
    r5 = {
        "case_id": 5,
        "name": "Legitimate delivery OTP",
        "verdict": c5_rep.assessment.get("status"),
        "decision_rule": c5_rep.audit.get("final_decision_rule"),
        "passed": c5_rep.assessment.get("status") in ["likely_non_scam", "mixed_signals"] and c5_rep.audit.get("final_decision_rule") == "rule_p17_delivery_brand_disambiguation",
    }
    results.append(r5)
    print(f"Case 5 [Delivery OTP]: Verdict={r5['verdict']}, Rule={r5['decision_rule']} (Pass={r5['passed']})")

    # -------------------------------------------------------------
    # Case 6 — Suspicious URL only
    # -------------------------------------------------------------
    c6_in = InvestigationInput(
        url="http://192.168.1.50:8080/secure/bank/login.php",
        case_id="case_06_suspicious_url",
    )
    c6_rep = service.investigate(c6_in)
    r6 = {
        "case_id": 6,
        "name": "Suspicious URL only",
        "input_type": c6_rep.input_type,
        "url_findings_count": len(c6_rep.url_findings),
        "passed": c6_rep.input_type == "url_only" and len(c6_rep.url_findings) > 0,
    }
    results.append(r6)
    print(f"Case 6 [Suspicious URL]: Modality={r6['input_type']}, Findings={r6['url_findings_count']} (Pass={r6['passed']})")

    # -------------------------------------------------------------
    # Case 7 — Legitimate institutional URL
    # -------------------------------------------------------------
    c7_in = InvestigationInput(
        url="https://rbi.org.in",
        case_id="case_07_legit_url",
    )
    c7_rep = service.investigate(c7_in)
    r7 = {
        "case_id": 7,
        "name": "Legitimate institutional URL",
        "verdict": c7_rep.assessment.get("status"),
        "url_findings_count": len(c7_rep.url_findings),
        "passed": c7_rep.assessment.get("status") == "likely_non_scam" and len(c7_rep.url_findings) == 0,
    }
    results.append(r7)
    print(f"Case 7 [Legit institutional URL]: Verdict={r7['verdict']}, Findings={r7['url_findings_count']} (Pass={r7['passed']})")

    # -------------------------------------------------------------
    # Case 8 — Obfuscated scam
    # -------------------------------------------------------------
    c8_in = InvestigationInput(
        text="U-R-G-E-N-T: Y0ur b@nk @cc0unt is suspended. Update KYC now at bit.ly/kyc-alert",
        case_id="case_08_obfuscated",
    )
    c8_rep = service.investigate(c8_in)
    r8 = {
        "case_id": 8,
        "name": "Obfuscated scam",
        "verdict": c8_rep.assessment.get("status"),
        "passed": c8_rep.assessment.get("status") in ["likely_scam", "suspicious", "mixed_signals"],
    }
    results.append(r8)
    print(f"Case 8 [Obfuscated scam]: Verdict={r8['verdict']} (Pass={r8['passed']})")

    # -------------------------------------------------------------
    # Case 9 — Screenshot scan
    # -------------------------------------------------------------
    img = Image.new("RGB", (300, 100), color=(255, 255, 255))
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    img_bytes = buf.getvalue()

    c9_in = InvestigationInput(
        image_bytes=img_bytes,
        image_filename="synthetic_test.png",
        case_id="case_09_screenshot",
    )
    c9_rep = service.investigate(c9_in)
    r9 = {
        "case_id": 9,
        "name": "Screenshot scan",
        "input_type": c9_rep.input_type,
        "passed": "image" in c9_rep.input_type and c9_rep.assessment.get("status") is not None,
    }
    results.append(r9)
    print(f"Case 9 [Screenshot scan]: Modality={r9['input_type']} (Pass={r9['passed']})")

    # -------------------------------------------------------------
    # Case 10 — GenAI unavailable / fallback
    # -------------------------------------------------------------
    c10_in = InvestigationInput(
        text="Your PAN card is linked to an illegal tax refund. Call 9876543210 to settle penalty.",
        provider_name="mock",
        case_id="case_10_genai_fallback",
    )
    c10_rep = service.investigate(c10_in)
    r10 = {
        "case_id": 10,
        "name": "GenAI unavailable/fallback",
        "explanation_available": c10_rep.explanation_available,
        "provider": c10_rep.explanation.get("provider", "mock"),
        "passed": c10_rep.explanation_available and "summary" in c10_rep.explanation,
    }
    results.append(r10)
    print(f"Case 10 [GenAI fallback]: Available={r10['explanation_available']}, Provider={r10['provider']} (Pass={r10['passed']})")

    print("\n" + "=" * 70)
    all_passed = all(r["passed"] for r in results)
    print(f"PRODUCTION SMOKE TEST SUMMARY: {sum(r['passed'] for r in results)}/10 PASSED. ALL PASSED: {all_passed}")
    print("=" * 70)

    # Save to JSON
    out_path = PROJECT_ROOT / "data" / "metadata" / "phase18c_smoke_tests.json"
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(results, f, indent=2)
    print(f"Saved smoke test output to: {out_path}")
    return all_passed


if __name__ == "__main__":
    success = run_smoke_tests()
    sys.exit(0 if success else 1)
