"""Phase 18B — Streamlit UI Integration & Presentation Tests.

Verifies:
1. Module imports and entrypoints (app.py, src.app.streamlit_app).
2. Service singleton access and pre-warming.
3. Ephemeral session state and case history management.
4. Investigation report serialization and export readiness (JSON and Markdown).
5. OCR environment detection behavior.
6. Multi-signal investigation flow across Quick Scan, Deep Investigation, and URL paths.
7. Error and edge case handling (empty input, whitespace, long text).
"""

from datetime import datetime, timezone
import json
from pathlib import Path
import unittest
from unittest.mock import MagicMock, patch

import streamlit as st

import app
from src.app.schemas import InvestigationInput, InvestigationReport
from src.app.service import InvestigationService
from src.app.streamlit_app import (
    extract_report_signals,
    get_investigation_service,
    init_session_state,
    record_case_history,
    render_history_panel,
    render_risk_signals,
    render_similarity_novelty,
    render_tactics_panel,
    render_verdict_card,
)
from src.ocr.environment import OCREnvironmentDetector


class TestPhase18BStreamlitUI(unittest.TestCase):
    """Test suite for Phase 18B Streamlit UI and integration layer."""

    @classmethod
    def setUpClass(cls):
        """Initialize cached service singleton for tests."""
        cls.service = get_investigation_service()

    def setUp(self):
        """Reset session state before each test."""
        st.session_state.clear()
        init_session_state()

    def test_module_imports_and_entrypoint(self):
        """Verify that app.py and streamlit_app import cleanly and expose main."""
        self.assertTrue(hasattr(app, "main"))
        self.assertTrue(callable(app.main))
        from src.app import streamlit_app
        self.assertTrue(hasattr(streamlit_app, "main"))
        self.assertTrue(callable(streamlit_app.main))

    def test_service_singleton_retrieval(self):
        """Verify that get_investigation_service returns an active InvestigationService."""
        service = get_investigation_service()
        self.assertIsInstance(service, InvestigationService)
        self.assertIsNotNone(service.pipeline)

    def test_session_state_initialization(self):
        """Verify session state defaults are correctly established."""
        self.assertIn("investigation_history", st.session_state)
        self.assertIn("latest_report", st.session_state)
        self.assertIn("active_mode", st.session_state)
        self.assertEqual(st.session_state["investigation_history"], [])
        self.assertIsNone(st.session_state["latest_report"])
        self.assertEqual(st.session_state["active_mode"], "Quick Scan")

    def test_record_case_history(self):
        """Verify case history logging in memory."""
        # Create a sample mock report
        mock_report = InvestigationReport(
            case_id="case_ui_test_001",
            timestamp="2026-10-03T00:00:00Z",
            input_type="text_only",
            assessment={
                "status": "scam",
                "risk_score": 0.88,
                "evidence_level": "high",
                "signal_consistency": "convergent",
                "rationale": "High-risk urgent banking scam",
            },
            timings_ms={"total_ms": 42.5},
        )

        record_case_history(mock_report, preview_text="URGENT: Your account is suspended. Verify now.")

        history = st.session_state["investigation_history"]
        self.assertEqual(len(history), 1)
        entry = history[0]
        self.assertEqual(entry["case_id"], "case_ui_test_001")
        self.assertEqual(entry["verdict"], "scam")
        self.assertEqual(entry["evidence_level"], "HIGH")
        self.assertEqual(entry["latency_ms"], 42.5)
        self.assertEqual(entry["preview"], "URGENT: Your account is suspended. Verify now.")
        self.assertIs(st.session_state["latest_report"], mock_report)

        # Add second item to verify LIFO ordering (newest first)
        mock_report_2 = InvestigationReport(
            case_id="case_ui_test_002",
            timestamp="2026-10-03T00:01:00Z",
            input_type="text_only",
            assessment={
                "status": "suspicious",
                "evidence_level": "medium",
                "signal_consistency": "convergent",
            },
            timings_ms={"total_ms": 31.0},
        )
        record_case_history(mock_report_2, preview_text="Second inquiry")
        self.assertEqual(len(st.session_state["investigation_history"]), 2)
        self.assertEqual(st.session_state["investigation_history"][0]["case_id"], "case_ui_test_002")

    def test_quick_scan_investigation_flow(self):
        """Verify live pipeline execution with typical scam input."""
        inp = InvestigationInput(
            text="URGENT: Electricity will be disconnected tonight. Pay immediately at bit.ly/power-bill",
        )
        report = self.service.investigate(inp)
        self.assertIsInstance(report, InvestigationReport)
        self.assertIn(
            report.assessment["status"],
            ["likely_scam", "likely_non_scam", "mixed_signals", "insufficient_evidence"],
        )
        self.assertGreater(report.timings_ms["total_ms"], 0.0)
        self.assertIn("status", report.assessment)
        self.assertIn("evidence_level", report.assessment)

    def test_url_only_investigation_flow(self):
        """Verify URL-only input path routing and passive evaluation."""
        inp = InvestigationInput(
            url="http://192.168.1.100:8080/secure/login.php?ref=bank",
        )
        report = self.service.investigate(inp)
        self.assertIsInstance(report, InvestigationReport)
        self.assertIn("url_findings", dir(report))
        self.assertEqual(report.input_type, "url_only")

    def test_ocr_environment_detector(self):
        """Verify OCR environment detection returns structured inspection dictionary."""
        inspection = OCREnvironmentDetector.inspect()
        self.assertIsInstance(inspection, dict)
        self.assertIn("installed", inspection)
        self.assertIn("version", inspection)
        self.assertIn("status", inspection)
        self.assertIsInstance(inspection["installed"], bool)

    def test_report_json_and_markdown_export(self):
        """Verify that an InvestigationReport can be serialized cleanly to JSON and Markdown."""
        inp = InvestigationInput(
            text="Your courier package #8921 is pending. Update address: http://delivery-tracking.info",
        )
        report = self.service.investigate(inp)
        dumped_dict = report.to_dict()
        json_str = json.dumps(dumped_dict, indent=2, default=str)
        self.assertIsInstance(json_str, str)
        self.assertIn("case_id", json_str)
        self.assertIn("assessment", json_str)
        # Verify valid round-trip parse
        parsed = json.loads(json_str)
        self.assertEqual(parsed["case_id"], report.case_id)

        # Verify markdown export
        md_str = report.to_markdown()
        self.assertIsInstance(md_str, str)
        self.assertIn(report.case_id, md_str)
        self.assertIn("Deterministic Case Assessment", md_str)

    def test_edge_case_whitespace_input(self):
        """Verify handling of empty or whitespace input."""
        inp = InvestigationInput(text="   \n\t  ")
        report = self.service.investigate(inp)
        self.assertIsInstance(report, InvestigationReport)
        self.assertIn(report.assessment["status"], ["insufficient_evidence", "benign"])

    @patch("streamlit.subheader")
    @patch("streamlit.columns")
    @patch("streamlit.error")
    @patch("streamlit.success")
    @patch("streamlit.markdown")
    @patch("streamlit.warning")
    @patch("streamlit.info")
    def test_reproduce_production_attribute_error_and_verify_fix(
        self, mock_info, mock_warn, mock_md, mock_succ, mock_err, mock_cols, mock_sub
    ):
        """Reproduce exact production bug and verify the UI-only extraction fix."""
        mock_cols.side_effect = lambda n: [MagicMock() for _ in range(n if isinstance(n, int) else len(n))]

        inp = InvestigationInput(
            text="URGENT: Electricity will be disconnected tonight. Pay immediately at http://bit.ly/power-bill",
            url="http://bit.ly/power-bill",
        )
        report = self.service.investigate(inp)

        # 1. Exact reproduction: accessing report.signals directly causes AttributeError
        with self.assertRaises(AttributeError):
            _ = report.signals.get("classifier_probability")

        # 2. Verify extract_report_signals correctly extracts existing signals from native fields
        extracted = extract_report_signals(report)
        self.assertIsNotNone(extracted["classifier_probability"])
        self.assertIsInstance(extracted["classifier_probability"], float)
        self.assertGreaterEqual(extracted["classifier_probability"], 0.0)
        self.assertLessEqual(extracted["classifier_probability"], 1.0)
        self.assertIsNotNone(extracted["url_risk_score"])
        self.assertIsInstance(extracted["url_risk_score"], float)
        self.assertIsNotNone(extracted["tactics"])
        self.assertIn("urgency", extracted["tactics"])

        # 3. Verify render_risk_signals & render_similarity_novelty execute safely
        render_risk_signals(report)
        render_similarity_novelty(report)

        # 4. Verify missing signals display N/A without crashing
        mock_report = InvestigationReport(
            case_id="case_missing_signals",
            input_type="text_only",
            timestamp="2026-10-03T00:00:00Z",
            assessment={"status": "insufficient_evidence", "evidence_level": "low"},
        )
        extracted_missing = extract_report_signals(mock_report)
        self.assertIsNone(extracted_missing["classifier_probability"])
        self.assertIsNone(extracted_missing["url_risk_score"])
        render_risk_signals(mock_report)
        render_similarity_novelty(mock_report)

        # 5. Verify non-dict signals object without .get() is handled safely
        class CustomSignals:
            classifier_probability = 0.85
            url_risk_score = 0.55
            tactics = ["urgency", "impersonation"]
            semantic_novelty_score = 0.12

        mock_obj_report = MagicMock()
        mock_obj_report.signals = CustomSignals()
        mock_obj_report.url_findings = []
        mock_obj_report.evidence_by_source = {}
        mock_obj_report.detected_tactics = ["urgency"]
        mock_obj_report.semantic_context = {}
        extracted_obj = extract_report_signals(mock_obj_report)
        self.assertEqual(extracted_obj["classifier_probability"], 0.85)
        self.assertEqual(extracted_obj["url_risk_score"], 0.55)
        render_risk_signals(mock_obj_report)

    @patch("streamlit.subheader")
    @patch("streamlit.columns")
    @patch("streamlit.error")
    @patch("streamlit.success")
    @patch("streamlit.markdown")
    @patch("streamlit.warning")
    @patch("streamlit.info")
    @patch("streamlit.caption")
    @patch("streamlit.dataframe")
    def test_all_four_ui_workflows_rendering(
        self, mock_df, mock_cap, mock_info, mock_warn, mock_md, mock_succ, mock_err, mock_cols, mock_sub
    ):
        """Verify rendering across Quick Scan, Deep Investigation, Screenshot Scan, and Case History."""
        mock_cols.side_effect = lambda n: [MagicMock() for _ in range(n if isinstance(n, int) else len(n))]

        # Generate a live investigation report
        inp = InvestigationInput(
            text="URGENT: Bank account suspended. Verify at bit.ly/bank-auth",
        )
        report = self.service.investigate(inp)

        # 1. Quick Scan rendering components
        render_verdict_card(report, mode="quick")
        render_risk_signals(report)

        # 2. Deep Investigation rendering components
        render_verdict_card(report, mode="deep")
        render_risk_signals(report)
        render_tactics_panel(report)
        render_similarity_novelty(report)

        # 3. Screenshot Scan rendering components (image modality)
        mock_image_report = InvestigationReport(
            case_id="case_screenshot_test",
            input_type="image_only",
            timestamp="2026-10-03T00:00:00Z",
            assessment={"status": "likely_scam", "evidence_level": "high"},
            ocr_text="Dear Customer, your electricity connection will be disconnected today.",
        )
        render_verdict_card(mock_image_report, mode="deep")
        render_risk_signals(mock_image_report)

        # 4. Case History workflow
        record_case_history(report, preview_text="URGENT: Bank account suspended...")
        render_history_panel()
        self.assertGreaterEqual(len(st.session_state["investigation_history"]), 1)


if __name__ == "__main__":
    unittest.main()
