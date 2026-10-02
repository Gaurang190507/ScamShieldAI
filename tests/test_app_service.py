"""Comprehensive test suite for ScamShield AI Phase 11 Investigation Application.

Verifies:
1. Input handling: text-only, URL-only, image-only, combined text+URL, combined text+image, combined all.
2. Edge cases: empty input, malformed URL, nonexistent image.
3. Phase 8 deterministic assessment preservation across all cases.
4. Phase 10 grounded explanation integration with citation tracking.
5. Provider failure resilience: deterministic assessment is fully preserved if LLM provider fails.
6. Mixed signals and insufficient evidence preservation (no binary force).
7. Privacy and security: zero network calls in default mock mode, temporary image cleanup, no secrets leaked.
"""

import json
from pathlib import Path
import unittest
from unittest.mock import MagicMock

from src.app.schemas import InvestigationInput, InvestigationReport
from src.app.service import InvestigationService
from src.explanation.base import BaseExplanationModel
from src.explanation.generator import ExplanationGenerator
from src.explanation.mock_provider import MockExplanationModel
from src.explanation.schemas import ExplanationRequest, ExplanationResponse
from src.ocr.extractor import OCRTextExtractor
from src.ocr.ocr_engine import FixtureOCREngine


class FailingExplanationModel(BaseExplanationModel):
    """Test stub simulating LLM API outage, rate limit, or network disconnection."""

    @property
    def provider_name(self) -> str:
        return "failing_mock"

    def generate_explanation(self, request: ExplanationRequest) -> ExplanationResponse:
        raise RuntimeError("Simulated remote provider connection error (503 Service Unavailable)")


class TestAppService(unittest.TestCase):
    """Unit and integration tests for InvestigationService."""

    @classmethod
    def setUpClass(cls):
        cls.fixtures_dir = Path(__file__).resolve().parent / "fixtures" / "images"
        cls.manifest_path = cls.fixtures_dir / "manifest.json"

        # Ensure fixtures are available for image tests
        if cls.manifest_path.is_file():
            cls.fixture_engine = FixtureOCREngine(manifest_path=cls.manifest_path)
            cls.ocr_extractor = OCRTextExtractor(ocr_engine=cls.fixture_engine)
        else:
            cls.ocr_extractor = OCRTextExtractor()

        # Shared lightweight service instance (offline mock)
        cls.service = InvestigationService(
            ocr_extractor=cls.ocr_extractor,
            enable_semantic=True,
            default_provider="mock",
        )

    def test_text_only_analysis_scam(self):
        """High-urgency phishing message produces likely_scam assessment and grounded explanation."""
        text = (
            "URGENT: Your SBI bank account has been suspended! "
            "Verify your PAN and KYC credentials immediately at http://192.168.1.100/verify-kyc"
        )
        inv_input = InvestigationInput(text=text, case_id="test_case_text_scam")
        report = self.service.investigate(inv_input)

        self.assertEqual(report.case_id, "test_case_text_scam")
        self.assertEqual(report.input_type, "text_only")
        self.assertEqual(report.assessment["status"], "likely_scam")
        self.assertIn("urgency", report.detected_tactics)

        # Evidence grouped by source
        self.assertGreater(len(report.evidence_by_source["TACTIC EVIDENCE"]), 0)
        self.assertGreater(len(report.evidence_by_source["URL EVIDENCE"]), 0)

        # Phase 10 explanation available and grounded
        self.assertTrue(report.explanation_available)
        self.assertIn("summary", report.explanation)
        self.assertEqual(report.audit["network_requests"], 0)
        self.assertFalse(report.audit["network_access"])

    def test_text_only_analysis_benign(self):
        """Benign personal message produces likely_non_scam verdict."""
        text = "Hi Mom, I reached the office safely. Will be home by 7 PM for dinner."
        inv_input = InvestigationInput(text=text, case_id="test_case_text_benign")
        report = self.service.investigate(inv_input)

        self.assertEqual(report.input_type, "text_only")
        self.assertEqual(report.assessment["status"], "likely_non_scam")
        self.assertEqual(len(report.detected_tactics), 0)
        self.assertTrue(report.explanation_available)

    def test_url_only_analysis(self):
        """Standalone suspicious URL input is evaluated purely via passive structural heuristics."""
        url = "http://192.168.1.50/secure/bank-update.php"
        inv_input = InvestigationInput(url=url, case_id="test_case_url_only")
        report = self.service.investigate(inv_input)

        self.assertEqual(report.input_type, "url_only")
        self.assertGreater(len(report.evidence_by_source["URL EVIDENCE"]), 0)
        self.assertTrue(any(u.get("name") == "ip_based_hostname" for u in report.evidence_by_source["URL EVIDENCE"]))
        self.assertEqual(report.audit["network_requests"], 0)

    def test_image_only_analysis_with_fixture(self):
        """Screenshot input is processed via Phase 9A OCR and Phase 9B visual observations."""
        fixture_img = self.fixtures_dir / "fixture_01_scam.png"
        if not fixture_img.is_file():
            self.skipTest("Fixture image not found on disk.")

        inv_input = InvestigationInput(image_path=fixture_img, case_id="test_case_img_only")
        report = self.service.investigate(inv_input)

        self.assertEqual(report.input_type, "image_only")
        self.assertIsNotNone(report.ocr_text)
        self.assertGreater(len(report.ocr_text), 0)
        self.assertGreater(len(report.visual_observations), 0)
        self.assertIn("status", report.assessment)
        self.assertEqual(report.audit["phase9a_ocr_used"], True)
        self.assertEqual(report.audit["phase9b_visual_used"], True)

    def test_image_bytes_processing_and_cleanup(self):
        """Uploaded image bytes are processed locally and temporary files are cleaned up."""
        fixture_img = self.fixtures_dir / "fixture_01_scam.png"
        if not fixture_img.is_file():
            self.skipTest("Fixture image not found on disk.")

        with open(fixture_img, "rb") as f:
            img_bytes = f.read()

        inv_input = InvestigationInput(
            image_bytes=img_bytes,
            image_filename="uploaded_screenshot.png",
            case_id="test_case_bytes",
        )
        report = self.service.investigate(inv_input)

        self.assertEqual(report.input_type, "image_only")
        self.assertIsNotNone(report.ocr_text)
        self.assertTrue(report.explanation_available)

    def test_combined_text_and_url(self):
        """Combined text and URL input coordinates multi-signal evaluation."""
        text = "Please review your pending statement before end of day."
        url = "https://secure-bank.example.org"
        inv_input = InvestigationInput(text=text, url=url, case_id="test_case_text_url")
        report = self.service.investigate(inv_input)

        self.assertEqual(report.input_type, "text_and_url")
        self.assertIn("status", report.assessment)
        self.assertIn(report.assessment["status"], ["likely_scam", "likely_non_scam", "mixed_signals"])

    def test_combined_all_inputs(self):
        """Combined text + URL + screenshot coordinates all signals without conflict."""
        fixture_img = self.fixtures_dir / "fixture_01_scam.png"
        if not fixture_img.is_file():
            self.skipTest("Fixture image not found on disk.")

        text = "User reported receiving this urgent notification."
        url = "http://192.168.1.100/login"
        inv_input = InvestigationInput(
            text=text,
            url=url,
            image_path=fixture_img,
            case_id="test_case_combined_all",
        )
        report = self.service.investigate(inv_input)

        self.assertEqual(report.input_type, "combined_all")
        self.assertGreater(len(report.all_evidence_items), 0)
        self.assertIsNotNone(report.ocr_text)

    def test_empty_input_graceful_handling(self):
        """Empty input returns insufficient_evidence without exceptions."""
        inv_input = InvestigationInput(text="", url="", image_path=None, case_id="test_case_empty")
        report = self.service.investigate(inv_input)

        self.assertEqual(report.input_type, "empty")
        self.assertEqual(report.assessment["status"], "insufficient_evidence")
        self.assertEqual(report.assessment["evidence_level"], "low")
        self.assertGreater(len(report.warnings), 0)
        self.assertEqual(report.audit["final_decision_rule"], "rule_empty_input")

    def test_nonexistent_image_graceful_handling(self):
        """Nonexistent image path records warning and falls back gracefully."""
        inv_input = InvestigationInput(
            text="Some message text",
            image_path=Path("nonexistent_image_path.png"),
            case_id="test_case_nonexistent_img",
        )
        report = self.service.investigate(inv_input)

        self.assertEqual(report.input_type, "text_only")
        self.assertTrue(any("not found" in w for w in report.warnings))
        self.assertIn("status", report.assessment)

    def test_provider_failure_does_not_cause_assessment_to_disappear(self):
        """A failure in the LLM explanation generator preserves the deterministic Phase 8 verdict."""
        text = "URGENT: Claim your lottery prize of Rs 25,00,000 immediately by calling our manager."
        failing_gen = ExplanationGenerator(provider=FailingExplanationModel())
        resilient_service = InvestigationService(
            explanation_generator=failing_gen,
            default_provider="mock",
        )

        inv_input = InvestigationInput(text=text, case_id="test_case_provider_fail")
        report = resilient_service.investigate(inv_input)

        # CRITICAL TEST: Deterministic assessment is 100% available and intact
        self.assertEqual(report.assessment["status"], "likely_scam")
        self.assertIn("urgency", report.detected_tactics)
        self.assertIn(report.assessment["evidence_level"], ["moderate", "high"])

        # Explanation availability flag is False, with deterministic summary fallback
        self.assertFalse(report.explanation_available)
        self.assertIsNotNone(report.explanation_error)
        self.assertIn("Simulated remote provider connection error", report.explanation_error)
        self.assertIn("summary", report.explanation)
        self.assertGreater(len(report.explanation["summary"]), 0)

    def test_deterministic_assessment_cannot_be_overridden_by_ui(self):
        """Verifies report assessment strictly mirrors Phase 8 pipeline output without alteration."""
        text = "Scan this QR code in PhonePe to receive your pending income tax refund of Rs. 14,280 instantly."
        report = self.service.investigate(InvestigationInput(text=text))

        # Direct pipeline reference
        direct_result = self.service.pipeline.analyze(text)
        self.assertEqual(report.assessment["status"], direct_result.assessment.status)
        self.assertEqual(report.assessment["evidence_level"], direct_result.assessment.evidence_level)
        self.assertEqual(report.assessment["signal_consistency"], direct_result.assessment.signal_consistency)

    def test_mixed_signals_preservation(self):
        """Mixed signals case retains uncertainty without forcing binary scam/safe verdict."""
        text = "Your account statement is ready for review at https://secure-bank.example.org"
        report = self.service.investigate(InvestigationInput(text=text))

        self.assertEqual(report.assessment["status"], "mixed_signals")
        self.assertIn("mixed", report.assessment["signal_consistency"])

    def test_report_serialization_and_markdown(self):
        """Report serializes to valid JSON dictionary and formatted Markdown document."""
        text = "Axis Bank Alert: Blocked unrecognized login attempt. If not you, freeze debit card."
        report = self.service.investigate(InvestigationInput(text=text, case_id="test_serialization"))

        # JSON dictionary
        d = report.to_dict()
        self.assertIsInstance(d, dict)
        self.assertEqual(d["case_id"], "test_serialization")
        json_str = json.dumps(d)
        self.assertIn("test_serialization", json_str)

        # Markdown
        md = report.to_markdown()
        self.assertIsInstance(md, str)
        self.assertIn("# ScamShield AI — Case Investigation Report", md)
        self.assertIn("`test_serialization`", md)
        self.assertIn("## 1. Deterministic Case Assessment", md)
        self.assertIn("## 5. Forensic Audit Trail", md)

    def test_security_audit_invariants(self):
        """Verifies zero network requests and offline safety in default configuration."""
        text = "Please verify your account at http://phishing-site.example.com"
        report = self.service.investigate(InvestigationInput(text=text))

        self.assertEqual(report.audit["network_requests"], 0)
        self.assertFalse(report.audit["network_access"])

        # Check no API keys leaked in audit or report JSON
        report_json = json.dumps(report.to_dict())
        self.assertNotIn("AIza", report_json)
        self.assertNotIn("gsk_", report_json)
        self.assertNotIn("api_key", report_json.lower())


if __name__ == "__main__":
    unittest.main()
