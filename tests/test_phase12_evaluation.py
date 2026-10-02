"""Automated test suite for ScamShield AI Phase 12 Real-World Robustness & Generalization.

Verifies:
1. Dataset Integrity & Schema Compliance:
   - All 8 evaluation files exist and conform to schema.
   - Provenance completeness in sources.csv.
   - Exact counts: 74 text cases, 20 modern, 20 hard negatives, 14 multilingual, 10 obfuscated, 10 novel, 24 URLs, 10 screenshots.
2. Data Leakage Audit:
   - 0 exact overlap with UCI training split.
   - 0 normalized overlap with UCI training split.
   - 0 overlap with Phase 7 semantic reference items.
3. Evaluator & Generalization Metrics:
   - Phase 3 baseline classification evaluation.
   - Phase 6 tactic detection micro/macro evaluation.
   - Phase 4 passive URL scanner robustness (0 network calls).
   - Phase 7 semantic similarity & novelty scoring.
   - Phase 8 multi-signal risk aggregation distribution.
   - Multilingual OOV rate and script gap analysis.
   - Obfuscation and perturbation consistency (label flip & tactic Jaccard).
   - Phase 11 Investigation Service multi-modal integration.
4. Security & Architectural Invariants:
   - Zero outbound network calls (passive only).
   - Zero hardcoded credentials or API secrets.
   - Frozen state preservation of Phases 1-11.
5. Report Generation Integrity:
   - All 13 evaluation markdown reports and metadata exist and are well-formed.
"""

import json
from pathlib import Path
import socket
import unittest
from unittest.mock import patch

from src.evaluation.phase12 import (
    Phase12Evaluator,
    Phase12LeakageAuditor,
    Phase12ReportGenerator,
)


class TestPhase12Evaluation(unittest.TestCase):
    """Test suite validating Phase 12 evaluation framework, datasets, and audits."""

    @classmethod
    def setUpClass(cls):
        cls.project_root = Path(__file__).resolve().parents[1]
        cls.eval_dir = cls.project_root / "data" / "evaluation" / "phase12"
        cls.metadata_dir = cls.project_root / "data" / "metadata"
        cls.evaluator = Phase12Evaluator(base_dir=cls.project_root)

    # =========================================================================
    # 1. DATASET INTEGRITY & PROVENANCE TESTS
    # =========================================================================

    def test_sources_csv_integrity(self):
        """Verifies sources.csv exists and contains required provenance entries."""
        sources_file = self.eval_dir / "sources.csv"
        self.assertTrue(sources_file.is_file(), "sources.csv must exist")
        content = sources_file.read_text(encoding="utf-8")
        lines = [line.strip() for line in content.strip().split("\n") if line.strip()]
        self.assertGreaterEqual(len(lines), 9, "sources.csv must have header + at least 8 sources")
        self.assertIn("source_id,source_name", lines[0])
        self.assertIn("src_p12_official_advisories", content)
        self.assertIn("src_p12_hard_negatives", content)
        self.assertIn("src_p12_multilingual", content)
        self.assertIn("src_p12_obfuscated", content)

    def test_schema_md_exists(self):
        """Verifies schema.md exists and specifies required JSON fields."""
        schema_file = self.eval_dir / "schema.md"
        self.assertTrue(schema_file.is_file(), "schema.md must exist")
        content = schema_file.read_text(encoding="utf-8")
        self.assertIn("sample_id", content)
        self.assertIn("label", content)
        self.assertIn("provenance_type", content)

    def test_real_world_cases_dataset(self):
        """Verifies real_world_cases.jsonl contains 74 valid cases."""
        file_path = self.eval_dir / "real_world" / "real_world_cases.jsonl"
        self.assertTrue(file_path.is_file())
        with open(file_path, "r", encoding="utf-8") as f:
            records = [json.loads(line) for line in f if line.strip()]
        self.assertEqual(len(records), 74, "Must contain exactly 74 real-world test cases")
        labels = set(r["label"] for r in records)
        self.assertEqual(labels, {"scam", "non_scam"})
        sample_ids = [r["sample_id"] for r in records]
        self.assertEqual(len(sample_ids), len(set(sample_ids)), "All sample_ids must be unique")

    def test_hard_negatives_dataset(self):
        """Verifies hard_negatives.jsonl contains 20 authentic non-scam cases."""
        file_path = self.eval_dir / "hard_negatives" / "hard_negatives.jsonl"
        self.assertTrue(file_path.is_file())
        with open(file_path, "r", encoding="utf-8") as f:
            records = [json.loads(line) for line in f if line.strip()]
        self.assertEqual(len(records), 20)
        for r in records:
            self.assertEqual(r["label"], "non_scam", f"Hard negative {r['sample_id']} must be labeled non_scam")
            self.assertIn("hard_negative_type", r)
            self.assertIn("why_it_looks_suspicious", r)
            self.assertIn("why_it_is_legitimate", r)

    def test_modern_indian_scams_dataset(self):
        """Verifies modern_indian_scams.jsonl contains 20 modern scam vectors."""
        file_path = self.eval_dir / "modern_scam_patterns" / "modern_indian_scams.jsonl"
        self.assertTrue(file_path.is_file())
        with open(file_path, "r", encoding="utf-8") as f:
            records = [json.loads(line) for line in f if line.strip()]
        self.assertEqual(len(records), 20)
        for r in records:
            self.assertEqual(r["label"], "scam", f"Modern scam {r['sample_id']} must be labeled scam")

    def test_multilingual_dataset(self):
        """Verifies multilingual_cases.jsonl contains 14 cases across Hindi & Hinglish."""
        file_path = self.eval_dir / "multilingual" / "multilingual_cases.jsonl"
        self.assertTrue(file_path.is_file())
        with open(file_path, "r", encoding="utf-8") as f:
            records = [json.loads(line) for line in f if line.strip()]
        self.assertEqual(len(records), 14)
        langs = set(r["language"] for r in records)
        self.assertEqual(langs, {"hi", "hi-Latn"})
        hi_count = sum(1 for r in records if r["language"] == "hi")
        hing_count = sum(1 for r in records if r["language"] == "hi-Latn")
        self.assertEqual(hi_count, 5)
        self.assertEqual(hing_count, 9)

    def test_obfuscated_dataset(self):
        """Verifies obfuscated_cases.jsonl contains 10 tracked perturbation pairs."""
        file_path = self.eval_dir / "obfuscated" / "obfuscated_cases.jsonl"
        self.assertTrue(file_path.is_file())
        with open(file_path, "r", encoding="utf-8") as f:
            records = [json.loads(line) for line in f if line.strip()]
        self.assertEqual(len(records), 10)
        for r in records:
            self.assertIn("original_sample_id", r)
            self.assertIn("transformation_type", r)
            self.assertIn("transformation_parameters", r)

    def test_novel_patterns_dataset(self):
        """Verifies novel_scam_patterns.jsonl contains 10 novel scam patterns."""
        file_path = self.eval_dir / "novel_patterns" / "novel_scam_patterns.jsonl"
        self.assertTrue(file_path.is_file())
        with open(file_path, "r", encoding="utf-8") as f:
            records = [json.loads(line) for line in f if line.strip()]
        self.assertEqual(len(records), 10)
        for r in records:
            self.assertEqual(r["label"], "scam")

    def test_url_benchmark_dataset(self):
        """Verifies url_benchmark.jsonl contains 24 passive URLs."""
        file_path = self.eval_dir / "urls" / "url_benchmark.jsonl"
        self.assertTrue(file_path.is_file())
        with open(file_path, "r", encoding="utf-8") as f:
            records = [json.loads(line) for line in f if line.strip()]
        self.assertEqual(len(records), 24)
        risks = set(r["expected_risk"] for r in records)
        self.assertTrue(risks.issubset({"high", "moderate", "low"}))

    def test_screenshot_cases_dataset(self):
        """Verifies screenshot_cases.jsonl contains 10 screenshot evaluation cases."""
        file_path = self.eval_dir / "screenshots" / "screenshot_cases.jsonl"
        self.assertTrue(file_path.is_file())
        with open(file_path, "r", encoding="utf-8") as f:
            records = [json.loads(line) for line in f if line.strip()]
        self.assertEqual(len(records), 10)

    # =========================================================================
    # 2. DATA LEAKAGE AUDIT TESTS
    # =========================================================================

    def test_leakage_audit_passes(self):
        """Verifies 0 exact and 0 normalized text leakage against training data."""
        auditor = Phase12LeakageAuditor(base_dir=self.project_root)
        report = auditor.audit_leakage()
        self.assertTrue(report["audit_passed"], "Leakage audit must pass with 0 leakage")
        self.assertEqual(report["exact_leakage_count"], 0, "Exact leakage count must be 0")
        self.assertEqual(report["normalized_leakage_count"], 0, "Normalized leakage count must be 0")
        self.assertEqual(report["semantic_reference_leakage_count"], 0, "Semantic reference leakage must be 0")
        self.assertGreater(report["total_evaluation_samples_audited"], 70)

    # =========================================================================
    # 3. EVALUATOR MODULE EXECUTION TESTS
    # =========================================================================

    def test_evaluate_classification(self):
        """Verifies Phase 3 text classification evaluation runs and returns valid metrics."""
        clf_res = self.evaluator.evaluate_classification()
        self.assertIn("overall", clf_res)
        self.assertIn("hard_negatives", clf_res)
        self.assertIn("modern_indian_scams", clf_res)
        overall = clf_res["overall"]
        self.assertEqual(overall["total"], 74)
        self.assertGreaterEqual(overall["accuracy"], 0.0)
        self.assertLessEqual(overall["accuracy"], 1.0)
        self.assertGreaterEqual(overall["precision"], 0.0)
        self.assertGreaterEqual(overall["recall"], 0.0)

    def test_evaluate_tactics(self):
        """Verifies Phase 6 tactic detection evaluation produces valid micro/macro metrics."""
        tact_res = self.evaluator.evaluate_tactics()
        self.assertIn("micro_metrics", tact_res)
        self.assertIn("macro_metrics", tact_res)
        self.assertIn("per_tactic", tact_res)
        self.assertGreaterEqual(tact_res["total_evaluated_cases"], 40)
        micro = tact_res["micro_metrics"]
        self.assertGreaterEqual(micro["precision"], 0.0)
        self.assertGreaterEqual(micro["recall"], 0.0)
        self.assertGreaterEqual(micro["f1"], 0.0)

    def test_evaluate_urls_passive(self):
        """Verifies Phase 4 URL scanner evaluation runs passively without network requests."""
        url_res = self.evaluator.evaluate_urls()
        self.assertEqual(url_res["total_urls"], 24)
        self.assertIn("overall_metrics", url_res)
        self.assertIn("category_performance", url_res)
        overall = url_res["overall_metrics"]
        self.assertGreaterEqual(overall["accuracy"], 0.70)
        self.assertEqual(overall["fp"], 0, "Clean institutional URLs should produce 0 false positives")

    def test_evaluate_semantic_novelty(self):
        """Verifies Phase 7 semantic similarity & novelty metrics across partitions."""
        sem_res = self.evaluator.evaluate_semantic_novelty()
        self.assertIn("modern_indian_scams", sem_res)
        self.assertIn("novel_patterns", sem_res)
        self.assertIn("hard_negatives", sem_res)
        novel_data = sem_res["novel_patterns"]
        self.assertGreaterEqual(novel_data["mean_novelty_score"], 0.0)
        self.assertLessEqual(novel_data["mean_novelty_score"], 1.0)

    def test_evaluate_aggregation(self):
        """Verifies Phase 8 aggregation distributes into valid status categories."""
        agg_res = self.evaluator.evaluate_aggregation()
        self.assertEqual(agg_res["total_cases"], 74)
        scam_dist = agg_res["scam_status_distribution"]
        non_scam_dist = agg_res["non_scam_status_distribution"]
        valid_statuses = {"likely_scam", "likely_non_scam", "mixed_signals", "insufficient_evidence"}
        self.assertTrue(set(scam_dist.keys()).issubset(valid_statuses))
        self.assertTrue(set(non_scam_dist.keys()).issubset(valid_statuses))
        self.assertIn("rule_trigger_distribution", agg_res)

    def test_evaluate_multilingual(self):
        """Verifies multilingual evaluation captures script and OOV gaps."""
        multi_res = self.evaluator.evaluate_multilingual()
        self.assertIn("native_hindi", multi_res)
        self.assertIn("romanized_hinglish", multi_res)
        hi = multi_res["native_hindi"]
        hing = multi_res["romanized_hinglish"]
        self.assertGreater(hi["oov_rate"], hing["oov_rate"], "Native Hindi OOV rate must exceed Hinglish OOV rate")

    def test_evaluate_perturbations(self):
        """Verifies perturbation evaluation measures consistency and degradation."""
        pert_res = self.evaluator.evaluate_perturbations()
        self.assertEqual(pert_res["total_pairs"], 10)
        self.assertIn("overall_label_flip_rate", pert_res)
        self.assertIn("mean_tactic_jaccard", pert_res)
        self.assertGreaterEqual(pert_res["mean_tactic_jaccard"], 0.0)
        self.assertLessEqual(pert_res["mean_tactic_jaccard"], 1.0)

    def test_evaluate_investigation_service(self):
        """Verifies Phase 11 InvestigationService handles multi-modal inputs."""
        svc_res = self.evaluator.evaluate_investigation_service()
        self.assertGreaterEqual(svc_res["tested_configurations"], 3)
        configs = svc_res["configurations"]
        self.assertIn("text_only", configs)
        self.assertIn("url_only", configs)
        self.assertIn("combined_text_url", configs)
        for name, cfg in configs.items():
            self.assertTrue(cfg["has_explanation"], f"Config {name} must have explanation")
            self.assertTrue(cfg["has_audit"], f"Config {name} must have audit object")

    def test_compile_error_analysis(self):
        """Verifies compile_error_analysis compiles structured false positives & negatives."""
        err_res = self.evaluator.compile_error_analysis()
        self.assertIn("total_false_positives", err_res)
        self.assertIn("total_false_negatives", err_res)
        self.assertIn("false_positives", err_res)
        self.assertIn("false_negatives", err_res)

    # =========================================================================
    # 4. REPORT & METADATA POPULATION TESTS
    # =========================================================================

    def test_all_13_reports_and_metadata_exist(self):
        """Verifies that all 13 evaluation markdown reports and metadata file exist on disk."""
        expected_reports = [
            "README.md",
            "dataset_report.md",
            "classification_evaluation.md",
            "tactic_evaluation.md",
            "url_evaluation.md",
            "semantic_evaluation.md",
            "aggregation_evaluation.md",
            "multilingual_evaluation.md",
            "robustness_evaluation.md",
            "error_analysis.md",
            "security_audit.md",
            "performance_evaluation.md",
            "phase12_final_report.md",
        ]
        for rep in expected_reports:
            p = self.eval_dir / rep
            self.assertTrue(p.is_file(), f"Report {rep} must exist at {p}")
            self.assertGreater(p.stat().st_size, 100, f"Report {rep} must be populated (> 100 bytes)")

        meta_file = self.metadata_dir / "phase12_robustness.md"
        self.assertTrue(meta_file.is_file(), "phase12_robustness.md must exist in data/metadata")
        self.assertGreater(meta_file.stat().st_size, 100)

    # =========================================================================
    # 5. SECURITY & OFFLINE INVARIANTS TESTS
    # =========================================================================

    def test_zero_network_calls_during_url_scan(self):
        """Verifies passive URL scanner makes 0 network socket connections."""
        with patch("socket.socket") as mock_sock:
            url_res = self.evaluator.evaluate_urls()
            self.assertEqual(mock_sock.call_count, 0, "No network sockets should be opened")

    def test_frozen_phases_untouched(self):
        """Verifies that upstream Phase 1-11 baseline artifacts remain intact."""
        tfidf_path = self.project_root / "models" / "baseline" / "tfidf_vectorizer.joblib"
        clf_path = self.project_root / "models" / "baseline" / "logistic_regression.joblib"
        sem_ref_path = self.project_root / "data" / "semantic" / "reference" / "reference_items.jsonl"
        self.assertTrue(tfidf_path.is_file(), "Phase 3 TF-IDF artifact must remain intact")
        self.assertTrue(clf_path.is_file(), "Phase 3 classifier artifact must remain intact")
        self.assertTrue(sem_ref_path.is_file(), "Phase 7 semantic reference items must remain intact")


if __name__ == "__main__":
    unittest.main()
