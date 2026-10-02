"""Comprehensive unit test suite for ScamShield AI Phase 4: Passive URL Analysis.

Tests:
1. Basic HTTPS URL parsing and low risk.
2. Basic HTTP URL and insecure transport signal.
3. IP-based URLs (IPv4 and IPv6).
4. Punycode hostnames.
5. Non-ASCII hostnames.
6. Subdomain depth (standard vs excessive).
7. Port analysis (standard vs non-standard).
8. Path features (length, percent-encoding, sensitive keywords).
9. Query features (parameter count, redirect parameters).
10. Known URL shorteners vs regular domains.
11. Userinfo credentials embedded before host.
12. Crash-resistance on malformed and non-string inputs.
13. Determinism across repeated executions.
14. Security boundary (AST audit guaranteeing zero outbound network libraries).
15. Explainability contract and absence of single-signal malicious verdict.
16. URLScanner wrapper backwards compatibility.
17. Batch dataset URL analysis output generation.
"""

import ast
import json
from pathlib import Path
import unittest

from src.url_analysis import (
    analyze_url,
    URLScanner,
    parse_url,
    extract_url_features,
    evaluate_url_heuristics,
)
from src.url_analysis.analyze_dataset_urls import run_batch_url_analysis


class TestPhase4URLAnalysis(unittest.TestCase):
    """Test suite covering Phase 4 offline URL analysis and threat heuristics."""

    def test_01_basic_https_url(self):
        """Test 1: Standard HTTPS URL parses successfully with low risk and zero threat signals."""
        res = analyze_url("https://example.com/about/team")
        self.assertTrue(res["parse_success"])
        self.assertIsNone(res["error_message"])
        self.assertTrue(res["features"]["is_https"])
        self.assertFalse(res["features"]["is_http"])
        self.assertEqual(res["features"]["hostname"], "example.com")
        self.assertEqual(res["features"]["path_depth"], 2)
        self.assertEqual(res["risk_score"], 0.0)
        self.assertEqual(res["risk_level"], "low")
        self.assertEqual(len(res["signals"]), 0)

    def test_02_basic_http_url(self):
        """Test 2: Standard HTTP URL triggers low-severity insecure transport heuristic signal."""
        res = analyze_url("http://example.com/blog")
        self.assertTrue(res["parse_success"])
        self.assertTrue(res["features"]["is_http"])
        self.assertFalse(res["features"]["is_https"])

        signals = [s["signal"] for s in res["signals"]]
        self.assertIn("insecure_http", signals)
        self.assertEqual(res["risk_level"], "low")
        self.assertGreater(res["risk_score"], 0.0)
        self.assertLess(res["risk_score"], 0.25)

    def test_03_ip_based_urls(self):
        """Test 3: Raw IPv4 and IPv6 URLs trigger ip_based_hostname heuristic."""
        # IPv4
        res_v4 = analyze_url("http://192.168.1.10/login")
        self.assertTrue(res_v4["parse_success"])
        self.assertTrue(res_v4["features"]["is_ip_hostname"])
        self.assertTrue(res_v4["features"]["is_ipv4"])
        self.assertFalse(res_v4["features"]["is_ipv6"])

        signals_v4 = {s["signal"]: s for s in res_v4["signals"]}
        self.assertIn("ip_based_hostname", signals_v4)
        self.assertEqual(signals_v4["ip_based_hostname"]["severity"], "medium")
        self.assertIn("192.168.1.10", signals_v4["ip_based_hostname"]["evidence"])

        # IPv6
        res_v6 = analyze_url("http://[2001:db8::1]:8080/path")
        self.assertTrue(res_v6["parse_success"])
        self.assertTrue(res_v6["features"]["is_ip_hostname"])
        self.assertTrue(res_v6["features"]["is_ipv6"])
        self.assertFalse(res_v6["features"]["is_ipv4"])
        signals_v6 = {s["signal"]: s for s in res_v6["signals"]}
        self.assertIn("ip_based_hostname", signals_v6)

    def test_04_punycode_hostname(self):
        """Test 4: Punycode internationalized domains trigger punycode_hostname signal."""
        res = analyze_url("http://xn--80akhbyknj4f.xn--p1ai/index.html")
        self.assertTrue(res["parse_success"])
        self.assertTrue(res["features"]["has_punycode"])
        signals = {s["signal"]: s for s in res["signals"]}
        self.assertIn("punycode_hostname", signals)
        self.assertEqual(signals["punycode_hostname"]["severity"], "medium")

    def test_05_non_ascii_hostname(self):
        """Test 5: Hostnames containing non-ASCII characters trigger non_ascii_hostname."""
        res = analyze_url("https://münchen.de/news")
        self.assertTrue(res["parse_success"])
        self.assertTrue(res["features"]["has_non_ascii_hostname"])
        signals = {s["signal"]: s for s in res["signals"]}
        self.assertIn("non_ascii_hostname", signals)
        self.assertEqual(signals["non_ascii_hostname"]["severity"], "low")

    def test_06_subdomain_depth(self):
        """Test 6: Deeply nested subdomains trigger excessive_subdomain_depth, normal does not."""
        # Normal single subdomain
        res_norm = analyze_url("https://mail.google.com/")
        self.assertEqual(res_norm["features"]["subdomain_count"], 1)
        self.assertFalse(res_norm["features"]["excessive_subdomain_depth"])

        # Excessive 4-level subdomain
        res_deep = analyze_url("https://login.account.security.verify.example.com/")
        self.assertGreaterEqual(res_deep["features"]["subdomain_count"], 3)
        self.assertTrue(res_deep["features"]["excessive_subdomain_depth"])
        signals = {s["signal"]: s for s in res_deep["signals"]}
        self.assertIn("excessive_subdomain_depth", signals)
        self.assertEqual(signals["excessive_subdomain_depth"]["severity"], "medium")

    def test_07_port_analysis(self):
        """Test 7: Non-standard ports trigger unusual_port signal, standard ports do not."""
        # Standard HTTPS 443
        res_std = analyze_url("https://example.com:443/")
        self.assertTrue(res_std["features"]["has_port"])
        self.assertFalse(res_std["features"]["has_unusual_port"])

        # Unusual port 8080
        res_unusual = analyze_url("http://example.com:8080/")
        self.assertTrue(res_unusual["features"]["has_port"])
        self.assertTrue(res_unusual["features"]["has_unusual_port"])
        signals = {s["signal"]: s for s in res_unusual["signals"]}
        self.assertIn("unusual_port", signals)
        self.assertEqual(signals["unusual_port"]["severity"], "medium")

    def test_08_path_features(self):
        """Test 8: Path keyword triggers, percent encoding, and length thresholds."""
        # Sensitive keywords
        res_kw = analyze_url("https://example.com/account/login/verify")
        self.assertIn("login", res_kw["features"]["suspicious_path_keywords"])
        self.assertIn("verify", res_kw["features"]["suspicious_path_keywords"])
        signals_kw = {s["signal"]: s for s in res_kw["signals"]}
        self.assertIn("suspicious_path_keywords", signals_kw)

        # Percent encoding
        res_enc = analyze_url("https://example.com/%20%21%22%23%24")
        self.assertGreaterEqual(res_enc["features"]["percent_encoded_count"], 3)
        signals_enc = {s["signal"]: s for s in res_enc["signals"]}
        self.assertIn("excessive_percent_encoding", signals_enc)

        # Excessive path length
        long_path = "a" * 80
        res_long = analyze_url(f"https://example.com/{long_path}")
        self.assertTrue(res_long["features"]["is_excessive_path_length"])

    def test_09_query_features(self):
        """Test 9: Query parameter counts and sensitive redirection parameter detection."""
        # Normal query
        res_norm = analyze_url("https://example.com/search?q=test&lang=en")
        self.assertEqual(res_norm["features"]["query_params_count"], 2)
        self.assertEqual(len(res_norm["features"]["suspicious_query_params"]), 0)

        # Suspicious redirect & token params
        res_red = analyze_url("https://example.com/auth?redirect=http://evil.com&token=secret123")
        self.assertIn("redirect", res_red["features"]["suspicious_query_params"])
        self.assertIn("token", res_red["features"]["suspicious_query_params"])
        signals = {s["signal"]: s for s in res_red["signals"]}
        self.assertIn("suspicious_query_parameters", signals)

    def test_10_url_shorteners(self):
        """Test 10: Known URL shortening services trigger known_shortener signal."""
        res_short = analyze_url("https://bit.ly/3xyz789")
        self.assertTrue(res_short["features"]["is_known_shortener"])
        signals = {s["signal"]: s for s in res_short["signals"]}
        self.assertIn("known_shortener", signals)
        self.assertEqual(signals["known_shortener"]["severity"], "low")

        res_norm = analyze_url("https://github.com/torvalds/linux")
        self.assertFalse(res_norm["features"]["is_known_shortener"])

    def test_11_userinfo_present(self):
        """Test 11: Embedded credentials / userinfo triggers high-severity userinfo_present."""
        res = analyze_url("https://admin:secret@example.com/dashboard")
        self.assertTrue(res["features"]["has_userinfo"])
        self.assertEqual(res["features"]["userinfo"], "admin:secret")
        signals = {s["signal"]: s for s in res["signals"]}
        self.assertIn("userinfo_present", signals)
        self.assertEqual(signals["userinfo_present"]["severity"], "high")

    def test_12_malformed_inputs_never_crash(self):
        """Test 12: Analyzer robustly handles malformed, empty, and non-string inputs without crashing."""
        malformed_inputs = [
            "",
            "   ",
            None,
            12345,
            ["https://example.com"],
            {"url": "test"},
            "http://",
            "https://",
            "http://:8080",
            "not a url at all",
            "http://[invalid_ipv6_bracket",
            "http://example.com:not_a_valid_port",
        ]
        for val in malformed_inputs:
            res = analyze_url(val)
            self.assertIsInstance(res, dict)
            self.assertFalse(res["parse_success"])
            self.assertEqual(res["risk_score"], 0.0)
            self.assertIn("parse_success", res)
            self.assertIn("signals", res)
            self.assertIn("features", res)

    def test_13_determinism(self):
        """Test 13: analyze_url produces identical output over repeated invocations."""
        test_url = "https://login.account.security.example.com/verify?token=abc&redirect=http://target.com"
        first_run = analyze_url(test_url)
        for _ in range(10):
            subsequent_run = analyze_url(test_url)
            self.assertEqual(first_run, subsequent_run)

    def test_14_offline_security_boundary(self):
        """Test 14: AST audit guarantees zero network libraries imported anywhere in src/url_analysis."""
        url_analysis_dir = Path(__file__).resolve().parents[1] / "src" / "url_analysis"
        forbidden_modules = {
            "requests",
            "urllib.request",
            "httpx",
            "aiohttp",
            "socket",
            "http.client",
            "urllib3",
            "selenium",
            "playwright",
        }

        for py_file in url_analysis_dir.glob("*.py"):
            with open(py_file, "r", encoding="utf-8") as f:
                tree = ast.parse(f.read(), filename=str(py_file))

            for node in ast.walk(tree):
                if isinstance(node, ast.Import):
                    for alias in node.names:
                        for forbidden in forbidden_modules:
                            self.assertFalse(
                                alias.name == forbidden or alias.name.startswith(f"{forbidden}."),
                                f"Forbidden network library '{alias.name}' imported in {py_file.name}",
                            )
                elif isinstance(node, ast.ImportFrom):
                    mod_name = node.module or ""
                    for forbidden in forbidden_modules:
                        self.assertFalse(
                            mod_name == forbidden or mod_name.startswith(f"{forbidden}."),
                            f"Forbidden network library '{mod_name}' imported in {py_file.name}",
                        )

    def test_15_explainability_contract(self):
        """Test 15: Signals contain evidence/reason, bounded scores, and no single-signal malicious verdict."""
        test_urls = [
            "http://185.12.44.21:8080/secure/login/kyc?token=xyz",
            "https://bit.ly/update-account",
            "https://admin:pass@evil.com/path",
        ]
        allowed_severities = {"low", "medium", "high"}
        allowed_levels = {"low", "moderate", "high", "very_high", "unknown"}

        for u in test_urls:
            res = analyze_url(u)
            # Ensure NO single-signal verdict field like "malicious: true"
            self.assertNotIn("malicious", res)
            self.assertNotIn("is_scam", res)

            # Check score bounds
            self.assertGreaterEqual(res["risk_score"], 0.0)
            self.assertLessEqual(res["risk_score"], 1.0)
            self.assertIn(res["risk_level"], allowed_levels)

            for sig in res["signals"]:
                self.assertIn("signal", sig)
                self.assertIn(sig["severity"], allowed_severities)
                self.assertGreater(sig["score"], 0.0)
                self.assertTrue(len(sig["evidence"]) > 0)
                self.assertTrue(len(sig["reason"]) > 0)

    def test_16_url_scanner_backwards_compatibility(self):
        """Test 16: URLScanner class extracts URLs from text and wraps analyze_url properly."""
        scanner = URLScanner()
        text = "Urgent: Visit http://192.168.1.1/login or check https://example.com"
        extracted = scanner.extract_urls(text)
        self.assertEqual(len(extracted), 2)
        self.assertIn("http://192.168.1.1/login", extracted)
        self.assertIn("https://example.com", extracted)

        res = scanner.analyze_url("https://example.com")
        self.assertTrue(res["parse_success"])
        self.assertEqual(res["features"]["hostname"], "example.com")

    def test_17_batch_analysis_utility(self):
        """Test 17: run_batch_url_analysis generates all evaluation artifacts cleanly."""
        summary = run_batch_url_analysis()
        self.assertIn("feature_statistics", summary)
        self.assertIn("signal_frequency", summary)
        self.assertIn("risk_distribution", summary)

        out_dir = Path(summary["output_dir"])
        self.assertTrue((out_dir / "url_analysis_results.jsonl").is_file())
        self.assertTrue((out_dir / "feature_statistics.json").is_file())
        self.assertTrue((out_dir / "signal_frequency.json").is_file())
        self.assertTrue((out_dir / "risk_distribution.json").is_file())
        self.assertTrue((out_dir / "README.md").is_file())


if __name__ == "__main__":
    unittest.main()
