"""Phase 16 Unit Test Suite: Real-World End-to-End Validation & Generalization Audit.

Verifies:
1. Phase 16 dataset manifest schema, field integrity, and PII redaction.
2. Zero data leakage / contamination against historical Phase 1-15 splits.
3. End-to-end evaluation execution, consistency, and report generation.
4. Authoritative SHA-256 integrity of all 5 frozen release artifacts.
5. End-to-end service behavior on representative test cases.
"""

import json
from pathlib import Path
import unittest

from src.app.schemas import InvestigationInput
from src.app.service import InvestigationService
from src.artifacts.manager import (
    FROZEN_ARTIFACT_CHECKSUMS,
    compute_file_sha256,
)
from src.evaluation.phase16.corpus_builder import get_all_samples
from src.evaluation.phase16.leakage_auditor import Phase16LeakageAuditor


class TestPhase16Validation(unittest.TestCase):
    """Test suite for Phase 16 validation and generalization audit."""

    @classmethod
    def setUpClass(cls):
        cls.root_dir = Path(__file__).resolve().parents[1]
        cls.eval_dir = cls.root_dir / "data" / "evaluation" / "phase16"
        cls.manifest_path = cls.eval_dir / "phase16_dataset_manifest.jsonl"
        cls.results_path = cls.eval_dir / "evaluation_results.json"

    def test_01_frozen_artifact_integrity_hashes(self):
        """Verifies that all 5 authoritative release artifacts match their exact frozen SHA-256 hashes."""
        paths = {
            "baseline_vectorizer": self.root_dir / "models" / "baseline" / "tfidf_vectorizer.joblib",
            "baseline_classifier": self.root_dir / "models" / "baseline" / "logistic_regression.joblib",
            "char_vectorizer": self.root_dir / "models" / "phase13" / "char_ngram" / "char_vectorizer.joblib",
            "char_classifier": self.root_dir / "models" / "phase13" / "char_ngram" / "char_classifier.joblib",
            "reference_embeddings": self.root_dir / "data" / "semantic" / "reference" / "reference_embeddings.npy",
        }

        for key, p in paths.items():
            self.assertTrue(p.exists(), f"Artifact file {p} does not exist.")
            expected_sha = FROZEN_ARTIFACT_CHECKSUMS[key]
            actual_sha = compute_file_sha256(p)
            self.assertEqual(
                actual_sha.lower(),
                expected_sha.lower(),
                f"Artifact {key} hash mismatch! Expected {expected_sha}, got {actual_sha}",
            )

    def test_02_dataset_manifest_schema_and_integrity(self):
        """Verifies Phase 16 manifest schema, completeness, sample count, and PII redaction."""
        self.assertTrue(self.manifest_path.exists(), "Manifest file not found.")

        samples = []
        with open(self.manifest_path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line:
                    samples.append(json.loads(line))

        self.assertEqual(len(samples), 90, "Expected exactly 90 Phase 16 validation samples.")

        required_fields = {
            "sample_id", "case_group", "input_type", "text", "image_path", "urls",
            "language", "script", "ground_truth_label", "scam_category_if_known",
            "known_unknown_status", "primary_tactics", "secondary_tactics",
            "requested_action", "target_asset", "impersonated_entity", "urgency_level",
            "payment_request", "credential_request", "otp_request", "source_type",
            "source_reference", "collection_date", "transformation", "provenance",
            "human_review_status", "label_confidence", "review_notes",
        }

        groups = set()
        labels = set()
        for s in samples:
            missing = required_fields - set(s.keys())
            self.assertEqual(len(missing), 0, f"Sample {s.get('sample_id')} missing fields: {missing}")
            groups.add(s["case_group"])
            labels.add(s["ground_truth_label"])

            # Verify PII masking: no real unmasked 10-digit Indian phone numbers
            text = s.get("text", "")
            self.assertNotRegex(
                text,
                r"\b[6-9]\d{9}\b",
                f"Sample {s['sample_id']} contains unredacted 10-digit Indian mobile number!",
            )

        self.assertEqual(labels, {"scam", "non_scam"})
        self.assertEqual(
            groups,
            {
                "C1_common_scams", "C2_unknown_emerging", "C3_hard_negatives",
                "C4_multilingual", "C5_obfuscated", "C6_url_cases",
                "C7_screenshot_cases", "C8_adversarial_injection",
            },
        )

    def test_03_zero_leakage_and_contamination(self):
        """Executes leakage audit asserting 0 exact or near-duplicate contaminations."""
        auditor = Phase16LeakageAuditor(self.root_dir)
        results = auditor.run_audit()

        self.assertFalse(results["leakage_detected"], "Phase 16 validation corpus contains leaked data!")
        self.assertEqual(len(results["exact_matches"]), 0, "Exact match contamination found.")
        self.assertEqual(len(results["normalized_matches"]), 0, "Normalized match contamination found.")
        self.assertEqual(len(results["near_duplicates"]), 0, "Near-duplicate contamination found.")

    def test_04_evaluation_results_mathematical_consistency(self):
        """Verifies evaluation results JSON exists and metrics are mathematically sound."""
        self.assertTrue(self.results_path.exists(), "evaluation_results.json not found.")

        with open(self.results_path, "r", encoding="utf-8") as f:
            res = json.load(f)

        m = res["metrics"]
        recs = res["records"]
        self.assertEqual(len(recs), 90)

        cls_m = m["classification"]
        tp = cls_m["tp"]
        fp = cls_m["fp"]
        tn = cls_m["tn"]
        fn = cls_m["fn"]

        self.assertEqual(tp + fp + tn + fn, 90)
        self.assertAlmostEqual(cls_m["accuracy"], (tp + tn) / 90, places=4)
        if tp + fp > 0:
            self.assertAlmostEqual(cls_m["precision"], tp / (tp + fp), places=4)
        if tp + fn > 0:
            self.assertAlmostEqual(cls_m["recall"], tp / (tp + fn), places=4)

    def test_05_live_pipeline_investigation_service(self):
        """Runs an end-to-end investigation through the real service to verify live execution."""
        service = InvestigationService(enable_semantic=True, default_provider="mock")

        test_input = InvestigationInput(
            text="URGENT: Your SBI account is suspended. Verify immediately at http://sbi-verify.top",
            url="http://sbi-verify.top",
            case_id="test_p16_live_case",
        )

        report = service.investigate(test_input)
        self.assertIsNotNone(report)
        self.assertEqual(report.case_id, "test_p16_live_case")
        self.assertIn("status", report.assessment)
        self.assertIn(report.assessment["status"], ["likely_scam", "likely_non_scam", "mixed_signals", "insufficient_evidence"])
        self.assertTrue(report.explanation_available)
        self.assertIsInstance(report.detected_tactics, list)

    def test_06_all_phase16_reports_exist_and_non_empty(self):
        """Verifies that all 10 required Phase 16 reports and metadata exist and are non-empty."""
        expected_reports = [
            self.root_dir / "data" / "metadata" / "phase16_frozen_state_audit.md",
            self.root_dir / "data" / "metadata" / "phase16_validation_architecture.md",
            self.root_dir / "data" / "evaluation" / "phase16" / "phase16_dataset_manifest.jsonl",
            self.root_dir / "data" / "evaluation" / "phase16" / "phase16_leakage_report.md",
            self.root_dir / "data" / "evaluation" / "phase16" / "phase16_validation_report.md",
            self.root_dir / "data" / "evaluation" / "phase16" / "phase16_failure_analysis.md",
            self.root_dir / "data" / "evaluation" / "phase16" / "phase16_case_studies.md",
            self.root_dir / "data" / "evaluation" / "phase16" / "phase16_performance_report.md",
            self.root_dir / "data" / "evaluation" / "phase16" / "phase16_security_regression_report.md",
            self.root_dir / "data" / "evaluation" / "phase16" / "phase16_generalization_report.md",
            self.root_dir / "data" / "evaluation" / "phase16" / "phase16_final_report.md",
        ]

        for p in expected_reports:
            self.assertTrue(p.exists(), f"Required Phase 16 report missing: {p}")
            self.assertGreater(p.stat().st_size, 50, f"Report {p} is empty or suspiciously small.")


if __name__ == "__main__":
    unittest.main()
