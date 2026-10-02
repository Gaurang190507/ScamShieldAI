"""Phase 18C — Deployment Smoke Test Suite (10 Real-World Scenarios).

Executes the 10 canonical release smoke tests against the frozen InvestigationService:
1. Benign text
2. Obvious scam
3. URL only
4. Mixed text + URL
5. Legitimate delivery OTP
6. Obfuscated scam
7. Screenshot / Image
8. Oversized input
9. Malformed image
10. GenAI unavailable (Mock fallback)
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
    print("SCAMSHIELD AI — PHASE 18C DEPLOYMENT SMOKE TESTS")
    print("=" * 70)

    service = InvestigationService()
    service.warmup()
    print("InvestigationService warmed up successfully.\n")

    results = []

    # -------------------------------------------------------------
    # Test 1 — Benign text
    # -------------------------------------------------------------
    t1_in = InvestigationInput(
        text="Hi Mom, I will be home by 7 PM tonight. Please keep dinner ready.",
        case_id="smoke_01_benign",
    )
    t1_rep = service.investigate(t1_in)
    r1 = {
        "test_id": 1,
        "name": "Benign text",
        "verdict": t1_rep.assessment.get("status"),
        "evidence_level": t1_rep.assessment.get("evidence_level"),
        "latency_ms": t1_rep.timings_ms.get("total_ms"),
        "passed": t1_rep.assessment.get("status") in ["likely_non_scam", "insufficient_evidence"],
    }
    results.append(r1)
    print(f"Test 1 [Benign text]: Verdict={r1['verdict']} (Pass={r1['passed']})")

    # -------------------------------------------------------------
    # Test 2 — Obvious scam
    # -------------------------------------------------------------
    t2_in = InvestigationInput(
        text="URGENT: Your SBI bank account will be blocked today due to pending KYC. Click http://sbi-kyc-update.xyz to verify immediately.",
        case_id="smoke_02_scam",
    )
    t2_rep = service.investigate(t2_in)
    r2 = {
        "test_id": 2,
        "name": "Obvious scam",
        "verdict": t2_rep.assessment.get("status"),
        "tactics": t2_rep.detected_tactics,
        "passed": t2_rep.assessment.get("status") == "likely_scam",
    }
    results.append(r2)
    print(f"Test 2 [Obvious scam]: Verdict={r2['verdict']}, Tactics={r2['tactics']} (Pass={r2['passed']})")

    # -------------------------------------------------------------
    # Test 3 — URL only
    # -------------------------------------------------------------
    t3_in = InvestigationInput(
        url="http://192.168.1.50:8080/ebill/login.php",
        case_id="smoke_03_url_only",
    )
    t3_rep = service.investigate(t3_in)
    r3 = {
        "test_id": 3,
        "name": "URL only",
        "input_type": t3_rep.input_type,
        "url_findings_count": len(t3_rep.url_findings),
        "passed": t3_rep.input_type == "url_only" and len(t3_rep.url_findings) > 0,
    }
    results.append(r3)
    print(f"Test 3 [URL only]: Modality={r3['input_type']}, Findings={r3['url_findings_count']} (Pass={r3['passed']})")

    # -------------------------------------------------------------
    # Test 4 — Mixed text + URL
    # -------------------------------------------------------------
    t4_in = InvestigationInput(
        text="Your electricity bill of Rs 4850 is overdue. Pay before 8 PM to prevent power cutoff: http://quick-pay-power.in",
        case_id="smoke_04_mixed",
    )
    t4_rep = service.investigate(t4_in)
    r4 = {
        "test_id": 4,
        "name": "Mixed text + URL",
        "verdict": t4_rep.assessment.get("status"),
        "has_url_findings": len(t4_rep.url_findings) > 0,
        "passed": t4_rep.assessment.get("status") in ["likely_scam", "suspicious", "mixed_signals"] and len(t4_rep.url_findings) > 0,
    }
    results.append(r4)
    print(f"Test 4 [Mixed text + URL]: Verdict={r4['verdict']} (Pass={r4['passed']})")

    # -------------------------------------------------------------
    # Test 5 — Legitimate delivery OTP (Phase 17 disambiguation)
    # -------------------------------------------------------------
    t5_in = InvestigationInput(
        text="Your Amazon delivery agent is out for delivery. Share delivery code 491024 with the driver at the door to receive your package.",
        case_id="smoke_05_delivery_otp",
    )
    t5_rep = service.investigate(t5_in)
    r5 = {
        "test_id": 5,
        "name": "Legitimate delivery OTP",
        "verdict": t5_rep.assessment.get("status"),
        "decision_rule": t5_rep.audit.get("final_decision_rule"),
        "passed": t5_rep.assessment.get("status") in ["likely_non_scam", "mixed_signals"] and t5_rep.audit.get("final_decision_rule") == "rule_p17_delivery_brand_disambiguation",
    }
    results.append(r5)
    print(f"Test 5 [Legitimate delivery OTP]: Verdict={r5['verdict']}, Rule={r5['decision_rule']} (Pass={r5['passed']})")

    # -------------------------------------------------------------
    # Test 6 — Obfuscated scam (Phase 17 normalization)
    # -------------------------------------------------------------
    t6_in = InvestigationInput(
        text="U-R-G-E-N-T: Y0ur b@nk @cc0unt is suspended. Update KYC now at bit.ly/kyc-alert",
        case_id="smoke_06_obfuscated",
    )
    t6_rep = service.investigate(t6_in)
    r6 = {
        "test_id": 6,
        "name": "Obfuscated scam",
        "verdict": t6_rep.assessment.get("status"),
        "passed": t6_rep.assessment.get("status") in ["likely_scam", "suspicious", "mixed_signals"],
    }
    results.append(r6)
    print(f"Test 6 [Obfuscated scam]: Verdict={r6['verdict']} (Pass={r6['passed']})")

    # -------------------------------------------------------------
    # Test 7 — Screenshot / Image
    # -------------------------------------------------------------
    # Create synthetic test image
    img = Image.new("RGB", (300, 100), color=(255, 255, 255))
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    img_bytes = buf.getvalue()

    t7_in = InvestigationInput(
        image_bytes=img_bytes,
        image_filename="synthetic_smoke_test.png",
        case_id="smoke_07_screenshot",
    )
    t7_rep = service.investigate(t7_in)
    r7 = {
        "test_id": 7,
        "name": "Screenshot / Image",
        "input_type": t7_rep.input_type,
        "visual_obs_count": len(t7_rep.visual_observations),
        "passed": "image" in t7_rep.input_type and t7_rep.assessment.get("status") is not None,
    }
    results.append(r7)
    print(f"Test 7 [Screenshot]: Modality={r7['input_type']} (Pass={r7['passed']})")

    # -------------------------------------------------------------
    # Test 8 — Oversized input (Phase 15 input guards)
    # -------------------------------------------------------------
    huge_text = "SPAM " * 15000  # ~75,000 characters
    t8_in = InvestigationInput(
        text=huge_text,
        case_id="smoke_08_oversized",
    )
    t8_rep = service.investigate(t8_in)
    r8 = {
        "test_id": 8,
        "name": "Oversized input",
        "bounded_safely": t8_rep.assessment.get("status") is not None,
        "warnings": t8_rep.warnings,
        "passed": t8_rep.assessment.get("status") is not None,
    }
    results.append(r8)
    print(f"Test 8 [Oversized input]: Status={t8_rep.assessment.get('status')} (Pass={r8['passed']})")

    # -------------------------------------------------------------
    # Test 9 — Malformed image
    # -------------------------------------------------------------
    bad_bytes = b"NOT_A_VALID_IMAGE_STREAM_GARBAGE_PAYLOAD\x00\xff\xee"
    t9_in = InvestigationInput(
        image_bytes=bad_bytes,
        image_filename="malformed.png",
        case_id="smoke_09_malformed_img",
    )
    t9_rep = service.investigate(t9_in)
    r9 = {
        "test_id": 9,
        "name": "Malformed image",
        "warning_present": any("image" in w.lower() for w in t9_rep.warnings),
        "passed": t9_rep.assessment.get("status") is not None and any("image" in w.lower() for w in t9_rep.warnings),
    }
    results.append(r9)
    print(f"Test 9 [Malformed image]: Warnings={t9_rep.warnings} (Pass={r9['passed']})")

    # -------------------------------------------------------------
    # Test 10 — GenAI unavailable (Mock fallback)
    # -------------------------------------------------------------
    t10_in = InvestigationInput(
        text="Your PAN card is linked to an illegal tax refund. Call 9876543210 to settle penalty.",
        provider_name="mock",
        case_id="smoke_10_genai_fallback",
    )
    t10_rep = service.investigate(t10_in)
    r10 = {
        "test_id": 10,
        "name": "GenAI unavailable / Mock fallback",
        "explanation_available": t10_rep.explanation_available,
        "explanation_provider": t10_rep.explanation.get("provider", "mock"),
        "passed": t10_rep.explanation_available and "summary" in t10_rep.explanation,
    }
    results.append(r10)
    print(f"Test 10 [GenAI fallback]: Available={r10['explanation_available']}, Provider={r10['explanation_provider']} (Pass={r10['passed']})")

    print("\n" + "=" * 70)
    all_passed = all(r["passed"] for r in results)
    print(f"SMOKE TEST SUMMARY: {sum(r['passed'] for r in results)}/10 PASSED. ALL PASSED: {all_passed}")
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
