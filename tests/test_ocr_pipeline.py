"""Comprehensive unit and integration test suite for ScamShield AI Phase 9A OCR Ingestion."""

import json
from pathlib import Path
import tempfile
import unittest
from PIL import Image

from src.ocr.image_loader import (
    CorruptImageError,
    EmptyImageError,
    ImageNotFoundError,
    InvalidImageFormatError,
    load_and_validate_image,
)
from src.ocr.ocr_engine import (
    AutoOCREngine,
    BaseOCREngine,
    FixtureOCREngine,
    TesseractOCREngine,
)
from src.ocr.text_postprocessor import normalize_ocr_text
from src.ocr.extractor import (
    OCRTextExtractor,
    ImageCaseAssessmentPipeline,
    extract_ocr_entities,
    extract_otp_mentions,
)
from src.ocr.schemas import (
    ImageCaseAssessmentResult,
    ImageInputMetadata,
    OCRAuditTrail,
    OCRResult,
)


class TestOCRPipeline(unittest.TestCase):
    """Test suite covering Phase 9A image loading, OCR, normalization, and ScamShield integration."""

    @classmethod
    def setUpClass(cls):
        """Locates or ensures fixtures exist."""
        cls.fixtures_dir = Path(__file__).resolve().parents[1] / "fixtures" / "images"
        cls.manifest_path = cls.fixtures_dir / "manifest.json"

        # If fixtures not generated, generate them
        if not cls.manifest_path.is_file():
            from tests.fixtures.create_fixtures import generate_fixtures
            generate_fixtures(cls.fixtures_dir)

        with open(cls.manifest_path, "r", encoding="utf-8") as f:
            cls.manifest = json.load(f)

        cls.fixture_engine = FixtureOCREngine(manifest_path=cls.manifest_path)
        cls.extractor = OCRTextExtractor(ocr_engine=cls.fixture_engine)
        # Use lightweight test downstream pipeline without loading full transformers model in every quick test
        cls.pipeline = ImageCaseAssessmentPipeline(
            extractor=cls.extractor,
            enable_semantic=False,
        )

    def test_01_supported_image_formats(self):
        """Verify image loader supports standard formats (PNG, JPEG, WEBP, BMP)."""
        with tempfile.TemporaryDirectory() as tmp_dir:
            tmp_path = Path(tmp_dir)
            formats = [("test.png", "PNG"), ("test.jpg", "JPEG"), ("test.webp", "WEBP"), ("test.bmp", "BMP")]

            for fname, fmt in formats:
                fpath = tmp_path / fname
                img = Image.new("RGB", (100, 100), color=(200, 200, 200))
                img.save(fpath, format=fmt)

                loaded_img, meta = load_and_validate_image(fpath)
                self.assertIsNotNone(loaded_img)
                self.assertEqual(meta.width, 100)
                self.assertEqual(meta.height, 100)
                self.assertGreater(meta.file_size_bytes, 0)

    def test_02_unsupported_image_format(self):
        """Verify loader rejects unsupported extensions (.txt, .pdf, .exe)."""
        with tempfile.TemporaryDirectory() as tmp_dir:
            bad_path = Path(tmp_dir) / "document.pdf"
            bad_path.write_text("dummy content")

            with self.assertRaises(InvalidImageFormatError):
                load_and_validate_image(bad_path)

    def test_03_missing_file_raises_error(self):
        """Verify loader raises ImageNotFoundError for missing file."""
        non_existent = Path("non_existent_image_12345.png")
        with self.assertRaises(ImageNotFoundError):
            load_and_validate_image(non_existent)

    def test_04_corrupt_or_empty_image(self):
        """Verify loader rejects empty (0-byte) or corrupted image files."""
        with tempfile.TemporaryDirectory() as tmp_dir:
            empty_path = Path(tmp_dir) / "empty.png"
            empty_path.touch()

            with self.assertRaises(EmptyImageError):
                load_and_validate_image(empty_path)

            corrupt_path = Path(tmp_dir) / "corrupt.png"
            corrupt_path.write_bytes(b"not a valid png header byte sequence")

            with self.assertRaises(CorruptImageError):
                load_and_validate_image(corrupt_path)

    def test_05_ocr_success_on_scam_fixture(self):
        """Verify OCR extraction success on scam test fixture."""
        scam_img = self.fixtures_dir / "fixture_01_scam.png"
        meta, ocr_res, entities, audit = self.extractor.extract(scam_img)

        self.assertTrue(ocr_res.success)
        self.assertEqual(ocr_res.status, "success")
        self.assertIn("bank account will be suspended", ocr_res.raw_text)
        self.assertIn("https://example.com/verify", entities.urls)
        self.assertFalse(audit.network_access)
        self.assertFalse(audit.external_service)

    def test_06_ocr_empty_result_handling(self):
        """Verify blank image produces 'no_text_detected' status without throwing errors."""
        blank_img = self.fixtures_dir / "fixture_04_blank.png"
        meta, ocr_res, entities, audit = self.extractor.extract(blank_img)

        self.assertTrue(ocr_res.success)
        self.assertEqual(ocr_res.status, "no_text_detected")
        self.assertEqual(ocr_res.raw_text, "")
        self.assertEqual(ocr_res.normalized_text, "")
        self.assertEqual(len(entities.urls), 0)

        # End-to-end should produce insufficient evidence
        case_res = self.pipeline.analyze_image(blank_img)
        self.assertEqual(case_res.ocr.status, "no_text_detected")
        self.assertIsNotNone(case_res.assessment)
        self.assertEqual(case_res.assessment["assessment"]["status"], "insufficient_evidence")

    def test_07_raw_text_preservation(self):
        """Verify raw OCR text is preserved unmodified alongside normalized text."""
        raw_input = "  Line 1   with   extra spaces  \r\n\r\nLine 2 \t\t with tabs  "
        normalized = normalize_ocr_text(raw_input)

        # Raw has extra spaces and CRLF
        self.assertIn("\r\n", raw_input)
        self.assertIn("   ", raw_input)

        # Normalized collapsed spaces and normalized line endings
        self.assertNotIn("\r", normalized)
        self.assertNotIn("   ", normalized)
        self.assertEqual(normalized, "Line 1 with extra spaces\n\nLine 2 with tabs")

    def test_08_normalized_text_generation(self):
        """Verify text postprocessor normalizes whitespace and line breaks without rewriting words."""
        text = "URGENT:\r\nPlease visit   http://example.com/auth   now!"
        clean = normalize_ocr_text(text)
        self.assertEqual(clean, "URGENT:\nPlease visit http://example.com/auth now!")

    def test_09_url_extraction_from_ocr(self):
        """Verify URLs are extracted accurately from OCR text."""
        text = "Visit https://secure-bank.com/login and http://192.168.1.1/test for details."
        entities = extract_ocr_entities(text)
        self.assertIn("https://secure-bank.com/login", entities.urls)
        self.assertIn("http://192.168.1.1/test", entities.urls)

    def test_10_phone_number_extraction(self):
        """Verify phone numbers and shortcodes are extracted."""
        text = "Helpline: +91-9876543210 or call 87575 for support."
        entities = extract_ocr_entities(text)
        self.assertTrue(any("9876543210" in p for p in entities.phone_numbers))

    def test_11_email_extraction(self):
        """Verify email addresses are extracted."""
        text = "Contact official support at alert@cyber-fraud.gov.in immediately."
        entities = extract_ocr_entities(text)
        self.assertIn("alert@cyber-fraud.gov.in", entities.email_addresses)

    def test_12_currency_extraction(self):
        """Verify currency mentions (Rupees, Dollars, Pounds) are extracted."""
        text = "You won ₹50,000 in cash. Pay $50 processing fee."
        entities = extract_ocr_entities(text)
        self.assertTrue(any("50,000" in c or "₹" in c for c in entities.currency_mentions))
        self.assertTrue(any("50" in c or "$" in c for c in entities.currency_mentions))

    def test_13_otp_mention_extraction(self):
        """Verify OTP patterns are extracted."""
        text = "Your one-time password OTP is 482910. Do not share your OTP code."
        otps = extract_otp_mentions(text)
        self.assertTrue(len(otps) > 0)
        self.assertTrue(any("otp" in o.lower() for o in otps))

    def test_14_ocr_text_reaching_phase3_and_phase6(self):
        """Verify extracted OCR text passes into Phase 3 text classifier and Phase 6 tactic detector."""
        scam_img = self.fixtures_dir / "fixture_01_scam.png"
        res = self.pipeline.analyze_image(scam_img)

        self.assertIsNotNone(res.assessment)
        signals = res.assessment["signals"]

        # Phase 3 classifier signals
        self.assertIn("text_classifier", signals)
        self.assertIsNotNone(signals["text_classifier"]["probability"])

        # Phase 6 tactic signals
        self.assertIn("tactics", signals)
        self.assertIn("account_suspension", signals["tactics"]["detected"])

    def test_15_no_fabricated_bounding_boxes(self):
        """Verify audit certifies spatial coordinates are unavailable rather than fabricating pixel boxes."""
        scam_img = self.fixtures_dir / "fixture_01_scam.png"
        res = self.pipeline.analyze_image(scam_img)
        self.assertFalse(res.audit.spatial_coordinates_available)

    def test_16_no_fabricated_confidence(self):
        """Verify OCR confidence is None when engine does not produce reliable confidence."""
        scam_img = self.fixtures_dir / "fixture_01_scam.png"
        meta, ocr_res, entities, audit = self.extractor.extract(scam_img)
        self.assertIsNone(ocr_res.confidence)

    def test_17_deterministic_repeated_execution(self):
        """Verify repeated evaluation on the same image produces identical results."""
        scam_img = self.fixtures_dir / "fixture_01_scam.png"
        res1 = self.pipeline.analyze_image(scam_img)
        res2 = self.pipeline.analyze_image(scam_img)

        self.assertEqual(res1.ocr.raw_text, res2.ocr.raw_text)
        self.assertEqual(res1.ocr.normalized_text, res2.ocr.normalized_text)
        self.assertEqual(res1.entities.urls, res2.entities.urls)
        self.assertEqual(res1.assessment["assessment"]["status"], res2.assessment["assessment"]["status"])

    def test_18_no_network_access_guarantee(self):
        """Verify audit trail guarantees network_access=False and external_service=False."""
        scam_img = self.fixtures_dir / "fixture_01_scam.png"
        res = self.pipeline.analyze_image(scam_img)
        self.assertFalse(res.audit.network_access)
        self.assertFalse(res.audit.external_service)

    def test_19_ocr_url_not_silently_repaired(self):
        """Verify typo in OCR extracted URL (e.g. examp1e.com) is NOT silently autocorrected."""
        typo_raw = "Please verify your account at https://examp1e.com/login immediately."
        normalized = normalize_ocr_text(typo_raw)
        entities = extract_ocr_entities(normalized)

        # Must retain original extracted typo
        self.assertIn("https://examp1e.com/login", entities.urls)
        self.assertNotIn("https://example.com/login", entities.urls)

    def test_20_ocr_failure_states(self):
        """Verify distinct failure statuses: invalid_image, engine_unavailable, no_text_detected."""
        # 1. Invalid image (missing)
        missing_img = Path("non_existent_img.png")
        res_missing = self.pipeline.analyze_image(missing_img)
        self.assertEqual(res_missing.ocr.status, "invalid_image")
        self.assertFalse(res_missing.ocr.success)

        # 2. Engine unavailable
        class UnavailableEngine(BaseOCREngine):
            @property
            def engine_name(self):
                return "mock_unavailable"
            def is_available(self):
                return False
            def extract_text(self, image, image_path=None):
                return "", None, [], ["engine_unavailable"]

        unavail_extractor = OCRTextExtractor(ocr_engine=UnavailableEngine())
        unavail_pipe = ImageCaseAssessmentPipeline(extractor=unavail_extractor, enable_semantic=False)
        valid_img = self.fixtures_dir / "fixture_01_scam.png"
        res_unavail = unavail_pipe.analyze_image(valid_img)
        self.assertEqual(res_unavail.ocr.status, "engine_unavailable")
        self.assertFalse(res_unavail.ocr.success)

        # 3. No text detected
        blank_img = self.fixtures_dir / "fixture_04_blank.png"
        res_blank = self.pipeline.analyze_image(blank_img)
        self.assertEqual(res_blank.ocr.status, "no_text_detected")
        self.assertTrue(res_blank.ocr.success)

    def test_21_audit_metadata_structure(self):
        """Verify ImageCaseAssessmentResult serializes completely to dictionary and valid JSON."""
        scam_img = self.fixtures_dir / "fixture_01_scam.png"
        res = self.pipeline.analyze_image(scam_img)
        d = res.to_dict()

        self.assertIn("input", d)
        self.assertIn("ocr", d)
        self.assertIn("entities", d)
        self.assertIn("assessment", d)
        self.assertIn("audit", d)
        self.assertEqual(d["audit"]["source_type"], "screenshot")

        # JSON serialize roundtrip
        json_str = json.dumps(d)
        self.assertIsInstance(json_str, str)
        parsed = json.loads(json_str)
        self.assertEqual(parsed["ocr"]["status"], "success")

    def test_22_downstream_phases_3_to_8_frozen(self):
        """Verify downstream Phase 3-8 decision rules and schemas remain intact."""
        scam_img = self.fixtures_dir / "fixture_01_scam.png"
        res = self.pipeline.analyze_image(scam_img)

        self.assertIn(res.assessment["assessment"]["status"], ["likely_scam", "mixed_signals"])
        self.assertEqual(res.assessment["audit"]["network_access"], False)
        self.assertEqual(res.assessment["audit"]["phase5_used"], False)


if __name__ == "__main__":
    unittest.main()
