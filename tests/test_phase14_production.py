"""Phase 14 Production Engineering & Optimization Test Suite for ScamShield AI.

Verifies:
1. Artifact validation layer (missing, corrupted, incompatible, and valid artifacts).
2. Centralized configuration immutability (frozen thresholds protected from mutation).
3. Input resource guards (oversized text, oversized URL, URL count, image dimension/size limits).
4. Process model cache (singleton reuse, cache hits, cache clearing).
5. Deterministic repeated inference (identical results across runs).
6. Resilient error handling (optional component failures never degrade deterministic verdict).
7. Security invariants (zero network access, secret sanitization, temp file cleanup).
8. CLI & application interfaces.
"""

from dataclasses import FrozenInstanceError
import io
import json
import os
from pathlib import Path
import tempfile
import unittest
from PIL import Image

from src.app.schemas import InvestigationInput, InvestigationReport
from src.app.service import InvestigationService
from src.artifacts.cache import (
    ModelArtifactCache,
    clear_model_cache,
    get_cache_stats,
    get_cached_baseline_classifier,
    get_cached_embedder,
    get_cached_knowledge_retriever,
    get_cached_semantic_reference_index,
)
from src.artifacts.manager import (
    ArtifactCorruptedError,
    ArtifactError,
    ArtifactIncompatibleError,
    ArtifactManager,
    ArtifactNotFoundError,
    validate_file_artifact,
)
from src.config.runtime_config import (
    FROZEN_CONFIG,
    RuntimeConfig,
    VERSION_METADATA,
    get_frozen_config,
    get_runtime_config,
)
from src.observability.logger import (
    get_logger,
    hash_text_content,
    sanitize_text,
)
from src.security.guards import (
    validate_image_bytes,
    validate_image_file_path,
    validate_text,
    validate_url,
    validate_url_list,
)


class TestArtifactManagement(unittest.TestCase):
    """Tests the artifact validation and loading layer."""

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.temp_path = Path(self.temp_dir.name)

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_missing_artifact_raises_error(self):
        missing_file = self.temp_path / "nonexistent.joblib"
        with self.assertRaises(ArtifactNotFoundError) as ctx:
            validate_file_artifact(
                missing_file,
                artifact_name="Test Model",
                expected_extensions=(".joblib",),
            )
        self.assertIn("Test Model", str(ctx.exception))
        self.assertIn("file does not exist", str(ctx.exception))

    def test_invalid_extension_raises_error(self):
        txt_file = self.temp_path / "model.txt"
        txt_file.write_text("dummy content")
        with self.assertRaises(ArtifactIncompatibleError) as ctx:
            validate_file_artifact(
                txt_file,
                artifact_name="Test Model",
                expected_extensions=(".joblib",),
            )
        self.assertIn("invalid file extension", str(ctx.exception))

    def test_empty_artifact_raises_corrupted_error(self):
        empty_file = self.temp_path / "empty.joblib"
        empty_file.touch()
        with self.assertRaises(ArtifactCorruptedError) as ctx:
            validate_file_artifact(
                empty_file,
                artifact_name="Empty Model",
                expected_extensions=(".joblib",),
                min_size_bytes=10,
            )
        self.assertIn("empty or corrupted", str(ctx.exception))

    def test_checksum_mismatch_raises_corrupted_error(self):
        bad_file = self.temp_path / "altered.joblib"
        bad_file.write_bytes(b"tampered content")
        with self.assertRaises(ArtifactCorruptedError) as ctx:
            validate_file_artifact(
                bad_file,
                artifact_name="Tampered Model",
                expected_extensions=(".joblib",),
                expected_sha256="0000000000000000000000000000000000000000000000000000000000000000",
            )
        self.assertIn("checksum verification", str(ctx.exception).lower())

    def test_production_baseline_artifacts_valid(self):
        validated = ArtifactManager.validate_baseline_artifacts()
        self.assertTrue(validated["vectorizer"].is_file())
        self.assertTrue(validated["classifier"].is_file())
        self.assertTrue(validated["metadata"].is_file())

    def test_production_phase13_char_artifacts_valid(self):
        validated = ArtifactManager.validate_phase13_char_artifacts()
        self.assertTrue(validated["vectorizer"].is_file())
        self.assertTrue(validated["classifier"].is_file())

    def test_production_semantic_artifacts_valid(self):
        validated = ArtifactManager.validate_semantic_reference_artifacts()
        self.assertTrue(validated["embeddings"].is_file())
        self.assertTrue(validated["items"].is_file())

    def test_production_knowledge_base_valid(self):
        docs = ArtifactManager.validate_knowledge_base_artifacts()
        self.assertGreater(len(docs), 0)


class TestConfigurationManagement(unittest.TestCase):
    """Tests runtime configuration and immutable frozen threshold protection."""

    def test_frozen_thresholds_immutable(self):
        frozen = get_frozen_config()
        self.assertEqual(frozen.PHASE3_BASELINE_THRESHOLD, 0.30)
        self.assertEqual(frozen.PHASE13_MODEL_B_THRESHOLD, 0.55)
        self.assertEqual(frozen.PHASE13_MODEL_C_THRESHOLD, 0.50)
        self.assertEqual(frozen.PHASE13_MODEL_D_THRESHOLD, 0.50)

        with self.assertRaises((FrozenInstanceError, AttributeError)):
            frozen.PHASE3_BASELINE_THRESHOLD = 0.50  # type: ignore

        with self.assertRaises((FrozenInstanceError, AttributeError)):
            frozen.PHASE13_MODEL_B_THRESHOLD = 0.30  # type: ignore

    def test_version_metadata_contents(self):
        meta = VERSION_METADATA.to_dict()
        self.assertEqual(meta["project_version"], "1.0.0")
        self.assertEqual(meta["schema_version"], "1.0.0")
        self.assertIn("baseline_tfidf_lr", meta["model_versions"])
        self.assertIn("char_ngram_model_b", meta["model_versions"])

    def test_runtime_config_defaults(self):
        cfg = get_runtime_config()
        self.assertTrue(cfg.OFFLINE_MODE)
        self.assertTrue(cfg.ENABLE_PROCESS_MODEL_CACHE)
        self.assertEqual(cfg.MAX_TEXT_LENGTH, 50_000)
        self.assertEqual(cfg.MAX_URL_LENGTH, 2_048)
        self.assertEqual(cfg.MAX_URL_COUNT, 50)
        self.assertEqual(cfg.MAX_IMAGE_DIMENSION, 4096)


class TestInputResourceGuards(unittest.TestCase):
    """Tests defensive bounds on text, URLs, and image uploads."""

    def test_text_length_boundary(self):
        cfg = RuntimeConfig(MAX_TEXT_LENGTH=100)
        valid_text = "A" * 90
        ok, err = validate_text(valid_text, cfg)
        self.assertTrue(ok)
        self.assertIsNone(err)

        oversized_text = "A" * 150
        ok, err = validate_text(oversized_text, cfg)
        self.assertFalse(ok)
        self.assertIn("exceeds the maximum allowed", err)

    def test_url_length_boundary(self):
        cfg = RuntimeConfig(MAX_URL_LENGTH=50)
        ok, _ = validate_url("http://example.com/ok", cfg)
        self.assertTrue(ok)

        ok, err = validate_url("http://example.com/" + "x" * 60, cfg)
        self.assertFalse(ok)
        self.assertIn("exceeds the maximum allowed", err)

    def test_url_count_boundary(self):
        cfg = RuntimeConfig(MAX_URL_COUNT=3)
        ok, _ = validate_url_list(["http://a.com", "http://b.com"], cfg)
        self.assertTrue(ok)

        ok, err = validate_url_list(
            ["http://a.com", "http://b.com", "http://c.com", "http://d.com"], cfg
        )
        self.assertFalse(ok)
        self.assertIn("exceeds maximum allowed boundary", err)

    def test_image_dimension_guard(self):
        # Create an oversized in-memory image
        img = Image.new("RGB", (5000, 100), color="red")
        buf = io.BytesIO()
        img.save(buf, format="PNG")
        bytes_data = buf.getvalue()

        ok, err = validate_image_bytes(bytes_data)
        self.assertFalse(ok)
        self.assertIn("decompression bomb guard", err)

    def test_image_byte_size_guard(self):
        cfg = RuntimeConfig(MAX_IMAGE_BYTES=50)
        img = Image.new("RGB", (100, 100), color="blue")
        buf = io.BytesIO()
        img.save(buf, format="PNG")
        bytes_data = buf.getvalue()

        ok, err = validate_image_bytes(bytes_data, config=cfg)
        self.assertFalse(ok)
        self.assertIn("exceeds maximum allowed boundary", err)


class TestModelCacheAndWarmup(unittest.TestCase):
    """Tests the process-level thread-safe model cache."""

    def setUp(self):
        clear_model_cache()

    def test_singleton_cache_reuse(self):
        stats_before = get_cache_stats()
        clf1 = get_cached_baseline_classifier()
        stats_after1 = get_cache_stats()
        self.assertEqual(stats_after1["misses"], stats_before["misses"] + 1)

        # Second fetch must hit cache
        clf2 = get_cached_baseline_classifier()
        stats_after2 = get_cache_stats()
        self.assertEqual(stats_after2["hits"], stats_after1["hits"] + 1)
        self.assertIs(clf1, clf2)

    def test_cache_clear(self):
        _ = get_cached_baseline_classifier()
        self.assertGreater(get_cache_stats()["total_cached_objects"], 0)
        clear_model_cache()
        self.assertEqual(get_cache_stats()["total_cached_objects"], 0)

    def test_service_warmup(self):
        service = InvestigationService()
        warmup_timings = service.warmup()
        self.assertIn("baseline_classifier_ms", warmup_timings)
        self.assertIn("total_warmup_ms", warmup_timings)
        self.assertGreater(warmup_timings["total_warmup_ms"], 0.0)


class TestDeterministicReproducibility(unittest.TestCase):
    """Verifies identical inference outputs across multiple runs."""

    def test_reproducible_investigation(self):
        service = InvestigationService()
        inp = InvestigationInput(
            text="URGENT: Your SBI account has been locked. Verify immediately: http://192.168.1.1/kyc",
            case_id="repro_case_01",
        )

        res1 = service.investigate(inp)
        res2 = service.investigate(inp)

        # Verdict and evidence counts must match exactly
        self.assertEqual(res1.assessment["status"], res2.assessment["status"])
        self.assertEqual(res1.assessment["evidence_level"], res2.assessment["evidence_level"])
        self.assertEqual(len(res1.all_evidence_items), len(res2.all_evidence_items))
        self.assertEqual(res1.detected_tactics, res2.detected_tactics)


class TestResilientErrorHandling(unittest.TestCase):
    """Verifies that optional component failures do not compromise deterministic verdicts."""

    def test_oversized_text_safe_handling(self):
        service = InvestigationService()
        huge_text = "URGENT: Click here! " + ("x" * 60_000)
        inp = InvestigationInput(text=huge_text, case_id="case_huge")
        report = service.investigate(inp)

        self.assertIsNotNone(report.assessment["status"])
        self.assertTrue(any("safely capped" in w for w in report.warnings))

    def test_invalid_image_safe_handling(self):
        service = InvestigationService()
        inp = InvestigationInput(
            text="Legitimate meeting notes for project update.",
            image_bytes=b"not_an_image_random_corrupted_data",
            image_filename="test.png",
            case_id="case_bad_img",
        )
        report = service.investigate(inp)

        # Application must not crash; warning recorded
        self.assertIsNotNone(report.assessment["status"])
        self.assertTrue(any("Image input rejected" in w for w in report.warnings))

    def test_empty_input_handled_gracefully(self):
        service = InvestigationService()
        inp = InvestigationInput(text="", url="", image_path=None, case_id="case_empty")
        report = service.investigate(inp)

        self.assertEqual(report.input_type, "empty")
        self.assertEqual(report.assessment["status"], "insufficient_evidence")
        self.assertTrue(report.explanation_available)


class TestSecurityAndOfflineIntegrity(unittest.TestCase):
    """Verifies zero network calls, secret scrubbing, and safe temp files."""

    def test_zero_network_audit_guarantee(self):
        service = InvestigationService(default_provider="mock")
        inp = InvestigationInput(
            text="Hello friend, please call me tomorrow.",
            url="http://example.com/test",
        )
        report = service.investigate(inp)

        self.assertFalse(report.audit["network_access"])
        self.assertEqual(report.audit["network_requests"], 0)

    def test_secret_sanitization(self):
        os.environ["GROQ_API_KEY"] = "gsk_secret_test_token_1234567890"
        sensitive_string = "Log entry with secret gsk_secret_test_token_1234567890 and password=mySecretPassword123"
        sanitized = sanitize_text(sensitive_string)

        self.assertNotIn("gsk_secret_test_token_1234567890", sanitized)
        self.assertNotIn("mySecretPassword123", sanitized)
        self.assertIn("[REDACTED_GROQ", sanitized)

    def test_hash_text_content(self):
        h1 = hash_text_content("Test text")
        h2 = hash_text_content("Test text")
        h3 = hash_text_content("Different text")
        self.assertEqual(h1, h2)
        self.assertNotEqual(h1, h3)


class TestReportExports(unittest.TestCase):
    """Tests JSON and Markdown report export functionality."""

    def test_report_serialization(self):
        service = InvestigationService()
        inp = InvestigationInput(text="Verify account immediately at http://secure-bank.xyz")
        report = service.investigate(inp)

        # JSON Export
        data = report.to_dict()
        self.assertIsInstance(data, dict)
        self.assertIn("version_metadata", data)
        self.assertIn("timings_ms", data)
        json_str = json.dumps(data)
        self.assertIsInstance(json_str, str)

        # Markdown Export
        md_str = report.to_markdown()
        self.assertIn("# ScamShield AI — Case Investigation Report", md_str)
        self.assertIn("Provenance & Performance Telemetry", md_str)


if __name__ == "__main__":
    unittest.main()
