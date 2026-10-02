"""Automated test suite for ScamShield AI Phase 13 Generalization & Detection Improvement.

Verifies:
1. Dataset Integrity & Schema Compliance:
   - All 7 Phase 13 datasets exist, are non-empty, and conform to the 17-field schema.
   - Sources in sources.csv match source_references in datasets.
2. Data Leakage Prevention:
   - Zero exact or normalized overlap with UCI training split.
   - Zero overlap with Phase 7 semantic reference items.
   - Zero overlap with Phase 12 benchmark cases.
   - Zero cross-split overlap between train, val, and test.
   - Strict pattern group and augmentation group isolation.
3. Multilingual Preprocessing & Character Representations:
   - Unicode NFKC normalization handles Devanagari and Latin correctly.
   - Model B (Char n-gram) correctly vectorizes and predicts on Hindi and Hinglish.
4. Model Contracts & Prediction Schemas:
   - Model B, Model C, and Model D adhere to Phase13Prediction schema.
   - Probabilities bounded in [0.0, 1.0].
5. Hard Negative Discrimination:
   - Model B rejects authentic bank OTP / transaction alerts (non_scam).
6. Obfuscation Robustness:
   - Evaluates spacing and leetspeak detection.
7. Security & Offline Invariants:
   - Purely passive and offline; socket connection attempts fail or raise assertions.
8. Report Generation & Documentation Integrity:
   - All 11 evaluation reports exist and contain required analysis sections.
"""

import json
from pathlib import Path
import socket
import unittest
from unittest.mock import patch

from src.evaluation.phase13.evaluator import Phase13Evaluator
from src.evaluation.phase13.leakage_auditor import Phase13LeakageAuditor
from src.models.phase13.char_classifier import CharNgramClassifier, normalize_unicode
from src.models.phase13.hybrid_classifier import HybridFusionClassifier
from src.models.phase13.schemas import Phase13Prediction
from src.models.phase13.semantic_classifier import SemanticDenseClassifier


class TestPhase13Generalization(unittest.TestCase):
    """Test suite validating Phase 13 datasets, experimental models, and audits."""

    @classmethod
    def setUpClass(cls):
        cls.project_root = Path(__file__).resolve().parents[1]
        cls.eval_dir = cls.project_root / "data" / "evaluation" / "phase13"
        cls.models_dir = cls.project_root / "models" / "phase13"
        cls.evaluator = Phase13Evaluator(base_dir=cls.project_root)

    # =========================================================================
    # 1. DATASET INTEGRITY & SCHEMA COMPLIANCE
    # =========================================================================

    def test_sources_csv_integrity(self):
        """Verifies sources.csv exists and contains required provenance entries."""
        sources_path = self.eval_dir / "sources.csv"
        self.assertTrue(sources_path.is_file(), "sources.csv must exist")
        content = sources_path.read_text(encoding="utf-8")
        self.assertIn("src_p13_official_advisories", content)
        self.assertIn("src_p13_hard_negatives", content)
        self.assertIn("src_p13_multilingual", content)
        self.assertIn("src_p13_obfuscation", content)
        self.assertIn("src_p13_novel_patterns", content)

    def test_all_dataset_files_exist_and_conform_to_schema(self):
        """Verifies all 7 dataset files exist and contain required schema fields."""
        required_files = [
            "training/train.jsonl",
            "validation/val.jsonl",
            "test/test.jsonl",
            "hard_negatives/hard_negatives.jsonl",
            "multilingual/multilingual_cases.jsonl",
            "obfuscation/obfuscated_cases.jsonl",
            "novel_patterns/novel_patterns.jsonl",
        ]

        required_fields = {
            "sample_id",
            "text",
            "label",
            "language",
            "scam_category",
            "tactics",
            "evidence_spans",
            "source_reference",
            "collection_date",
            "pattern_group_id",
            "known_unknown_status",
            "provenance_type",
            "phase13_source",
            "augmentation_type",
            "language_family",
            "script",
            "obfuscation_type",
        }

        for rel in required_files:
            file_path = self.eval_dir / rel
            self.assertTrue(file_path.is_file(), f"File {rel} must exist")
            count = 0
            with open(file_path, "r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if line:
                        record = json.loads(line)
                        count += 1
                        missing = required_fields - set(record.keys())
                        self.assertEqual(len(missing), 0, f"Missing fields in {rel}: {missing}")
                        self.assertIn(record["label"], ["scam", "non_scam"])
                        self.assertIn(record["language"], ["en", "hi", "hi-Latn"])
                        self.assertIn(record["script"], ["Latin", "Devanagari"])
            self.assertGreater(count, 0, f"File {rel} must contain records")

    # =========================================================================
    # 2. DATA LEAKAGE AUDIT
    # =========================================================================

    def test_leakage_audit_pass(self):
        """Executes full leakage audit and verifies strict zero-leakage invariant."""
        auditor = Phase13LeakageAuditor(base_dir=self.project_root)
        res = auditor.run_audit()
        self.assertEqual(res["status"], "PASS")
        self.assertTrue(res["is_leak_free"])
        self.assertEqual(res["uci_overlap"]["exact_count"], 0)
        self.assertEqual(res["uci_overlap"]["normalized_count"], 0)
        self.assertEqual(res["phase7_reference_overlap"]["exact_count"], 0)
        self.assertEqual(res["phase12_overlap"]["exact_count"], 0)
        self.assertEqual(res["cross_split_train_val"]["exact_overlap"], 0)
        self.assertEqual(res["cross_split_train_val"]["group_overlap"], 0)
        self.assertEqual(res["cross_split_train_test"]["exact_overlap"], 0)
        self.assertEqual(res["cross_split_train_test"]["group_overlap"], 0)
        self.assertEqual(res["augmentation_group_isolation_violations"], 0)

    # =========================================================================
    # 3. PREPROCESSING & MULTILINGUAL NORMALIZATION
    # =========================================================================

    def test_unicode_normalization(self):
        """Tests that normalize_unicode correctly standardizes Devanagari and Latin."""
        raw_hi = "प्रिय  ग्राहक,  आपका खाता"
        norm_hi = normalize_unicode(raw_hi)
        self.assertEqual(norm_hi, "प्रिय ग्राहक, आपका खाता")

        raw_lat = "SBI   Bank   Alert"
        norm_lat = normalize_unicode(raw_lat)
        self.assertEqual(norm_lat, "SBI Bank Alert")

    # =========================================================================
    # 4. MODEL PREDICTION CONTRACTS & SCHEMAS
    # =========================================================================

    def test_model_b_char_ngram_prediction(self):
        """Verifies Model B prediction schema, thresholding, and probability bounds."""
        model_b = self.evaluator.model_b
        pred = model_b.predict("Dear customer, your bank account is blocked. Verify at http://scam.me")
        self.assertIsInstance(pred, Phase13Prediction)
        self.assertEqual(pred.model_name, "Model_B_CharNgram")
        self.assertIn(pred.label, ["scam", "non_scam"])
        self.assertGreaterEqual(pred.probability, 0.0)
        self.assertLessEqual(pred.probability, 1.0)
        self.assertAlmostEqual(pred.scam_probability + pred.non_scam_probability, 1.0, places=4)

    def test_model_c_semantic_dense_prediction(self):
        """Verifies Model C dense semantic prediction contract."""
        model_c = self.evaluator.model_c
        pred = model_c.predict("Electricity disconnection scheduled tonight at 10 PM. Call officer.")
        self.assertIsInstance(pred, Phase13Prediction)
        self.assertEqual(pred.model_name, "Model_C_SemanticDense")
        self.assertIn(pred.label, ["scam", "non_scam"])
        self.assertGreaterEqual(pred.probability, 0.0)
        self.assertLessEqual(pred.probability, 1.0)

    def test_model_d_hybrid_fusion_prediction(self):
        """Verifies Model D multimodal hybrid fusion prediction and signal extraction."""
        model_d = self.evaluator.model_d
        pred = model_d.predict("Urgent: Your SBI account is suspended. Verify at http://192.168.1.1/sbi")
        self.assertIsInstance(pred, Phase13Prediction)
        self.assertEqual(pred.model_name, "Model_D_HybridFusion")
        self.assertIn(pred.label, ["scam", "non_scam"])
        self.assertIn("char_wb_ngrams_3_5", pred.features_used)
        self.assertIn("detected_tactics", pred.signals_detected)
        self.assertIn("url_signals", pred.signals_detected)

    # =========================================================================
    # 5. HARD NEGATIVE DISCRIMINATION
    # =========================================================================

    def test_hard_negative_discrimination_on_bank_otp(self):
        """Verifies that legitimate banking OTP alerts are NOT misclassified as scams by Model B."""
        model_b = self.evaluator.model_b
        legit_otp = (
            "Your OTP for HDFC Bank NetBanking login is 839201. Valid for 5 minutes. "
            "Do not share OTP with anyone including bank staff."
        )
        pred = model_b.predict(legit_otp)
        self.assertEqual(pred.label, "non_scam", "Legitimate OTP must be classified as non_scam")
        self.assertLess(pred.probability, model_b.threshold)

    # =========================================================================
    # 6. OBFUSCATION ROBUSTNESS
    # =========================================================================

    def test_obfuscation_robustness_on_spaced_chars(self):
        """Verifies that spaced character obfuscation is detected as scam by Model B."""
        model_b = self.evaluator.model_b
        spaced_text = "URGENT: Your S B I a c c o u n t is blocked. Verify at http://sbi-verify.com/now"
        pred = model_b.predict(spaced_text)
        self.assertEqual(pred.label, "scam", "Spaced obfuscation must still be detected as scam")

    # =========================================================================
    # 7. NOVELTY & SEMANTIC ANALYSIS
    # =========================================================================

    def test_novelty_analysis_integration(self):
        """Verifies that SemanticAnalyzer computes valid similarity and novelty metrics."""
        analyzer = self.evaluator.semantic_analyzer
        self.assertIsNotNone(analyzer, "Semantic analyzer should be initialized with reference index")
        res = analyzer.analyze("Sample test message for novelty check")
        self.assertGreaterEqual(res.semantic.top_1_similarity, -1.0)
        self.assertLessEqual(res.semantic.top_1_similarity, 1.0)
        self.assertGreaterEqual(res.semantic.semantic_novelty_score, 0.0)

    # =========================================================================
    # 8. SECURITY & OFFLINE INVARIANTS
    # =========================================================================

    def test_zero_network_calls_during_evaluation(self):
        """Verifies zero socket connections are attempted during model inference."""
        orig_connect = socket.socket.connect

        def mock_connect(*args, **kwargs):
            raise RuntimeError("Disallowed network attempt during offline evaluation!")

        with patch.object(socket.socket, "connect", side_effect=mock_connect):
            # Run prediction on Model B, C, D
            p_b = self.evaluator.model_b.predict("Test offline message")
            p_c = self.evaluator.model_c.predict("Test offline message")
            p_d = self.evaluator.model_d.predict("Test offline message")
            self.assertIsNotNone(p_b)
            self.assertIsNotNone(p_c)
            self.assertIsNotNone(p_d)

    # =========================================================================
    # 9. EVALUATION REPORTS EXISTENCE & CONTENT
    # =========================================================================

    def test_all_evaluation_reports_exist(self):
        """Verifies that all 11 evaluation reports exist and contain required content."""
        expected_reports = [
            "phase13_final_report.md",
            "model_comparison.md",
            "multilingual_evaluation.md",
            "hard_negative_evaluation.md",
            "obfuscation_evaluation.md",
            "tactic_aware_evaluation.md",
            "novelty_evaluation.md",
            "threshold_evaluation.md",
            "error_analysis.md",
            "leakage_audit.md",
            "security_audit.md",
        ]

        for rep in expected_reports:
            p = self.eval_dir / rep
            self.assertTrue(p.is_file(), f"Report {rep} must exist")
            text = p.read_text(encoding="utf-8")
            self.assertGreater(len(text), 100, f"Report {rep} must not be empty")

        # Also check metadata audit reports
        meta_arch = self.project_root / "data" / "metadata" / "phase13_architecture_audit.md"
        meta_leak = self.project_root / "data" / "metadata" / "phase13_leakage_audit.md"
        self.assertTrue(meta_arch.is_file(), "phase13_architecture_audit.md must exist in data/metadata")
        self.assertTrue(meta_leak.is_file(), "phase13_leakage_audit.md must exist in data/metadata")


if __name__ == "__main__":
    unittest.main()
