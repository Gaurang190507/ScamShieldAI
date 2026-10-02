"""Deterministic, explainable tactic detector for ScamShield AI.

Scans incoming message text against context-aware tactic rules, verifies
verbatim evidence spans, and produces structured TacticResult objects.
"""

from collections import defaultdict
from typing import Any, Dict, List, Optional
import re

from .evidence import EvidenceEngine
from .normalization import find_pattern_spans, is_contextually_negated
from .schemas import DetectedTactic, EvidenceSpan, TacticResult
from .tactic_rules import TACTIC_SEVERITY, TacticRule, build_tactic_rules
from src.preprocessing.extract_entities import extract_urls


class TacticDetector:
    """Core deterministic engine for scam tactic detection and evidence extraction."""

    def __init__(self, rules: Optional[List[TacticRule]] = None):
        """Initializes detector with default or custom tactic rules."""
        self.rules: List[TacticRule] = rules if rules is not None else build_tactic_rules()

    @property
    def rule_count(self) -> int:
        """Returns the total number of registered tactic rules."""
        return len(self.rules)

    def detect(
        self,
        text: str,
        sample_id: Optional[str] = None,
        urls: Optional[List[str]] = None,
    ) -> TacticResult:
        """Detects behavioral scam tactics and extracts grounded evidence spans from text.

        Args:
            text: Original message string.
            sample_id: Optional unique identifier for the sample.
            urls: Optional list of pre-extracted URLs.

        Returns:
            Structured TacticResult containing all detected tactics and evidence.
        """
        if not text or not isinstance(text, str):
            return TacticResult(text=text or "", sample_id=sample_id, tactics=[])

        # Accumulate raw candidate evidence spans grouped by tactic
        tactic_to_spans: Dict[str, List[EvidenceSpan]] = defaultdict(list)
        tactic_to_strength: Dict[str, str] = defaultdict(lambda: "medium")

        # 1. Match textual rules
        for rule in self.rules:
            matches = find_pattern_spans(text, rule.pattern)
            for start, end, matched_text in matches:
                # Check negative contextual filter if present
                if rule.negative_pattern and is_contextually_negated(
                    text, start, end, rule.negative_pattern, window=60
                ):
                    continue

                span = EvidenceSpan(
                    matched_text=matched_text,
                    start=start,
                    end=end,
                    rule_id=rule.rule_id,
                    severity=rule.severity,
                    reason=rule.reason,
                )

                # Validate offset integrity
                if EvidenceEngine.validate_span(text, span):
                    tactic_to_spans[rule.tactic].append(span)
                    if rule.evidence_strength == "high":
                        tactic_to_strength[rule.tactic] = "high"

        # 2. Integrate URLs from entities or preprocessing
        msg_urls = urls if urls is not None else extract_urls(text)
        if msg_urls:
            for url_str in msg_urls:
                # Find occurrences of the URL in original text
                escaped_url = re.escape(url_str)
                for m in re.finditer(escaped_url, text):
                    u_start, u_end = m.span()
                    url_span = EvidenceSpan(
                        matched_text=text[u_start:u_end],
                        start=u_start,
                        end=u_end,
                        rule_id="lnk_extracted_url_003",
                        severity="medium",
                        reason="Embedded URL redirects user to an external destination.",
                    )
                    if EvidenceEngine.validate_span(text, url_span):
                        tactic_to_spans["link_redirection"].append(url_span)
                        tactic_to_strength["link_redirection"] = "high"

        # 3. Assemble and deduplicate detected tactics
        detected_tactics: List[DetectedTactic] = []
        for tactic_name, raw_spans in tactic_to_spans.items():
            severity = TACTIC_SEVERITY.get(tactic_name, "medium")
            base_strength = tactic_to_strength[tactic_name]
            assembled = EvidenceEngine.assemble_tactic(
                tactic_name=tactic_name,
                severity=severity,
                raw_spans=raw_spans,
                base_strength=base_strength,
            )
            if assembled:
                detected_tactics.append(assembled)

        # Sort tactics: high severity first, then medium, then low, then alphabetical
        severity_rank = {"high": 0, "medium": 1, "low": 2}
        detected_tactics.sort(
            key=lambda t: (severity_rank.get(t.severity, 3), t.tactic)
        )

        return TacticResult(
            text=text,
            sample_id=sample_id,
            tactics=detected_tactics,
        )

    def detect_batch(
        self,
        records: List[Dict[str, Any]],
        text_field: str = "text",
        id_field: str = "sample_id",
        urls_field: str = "urls",
    ) -> List[TacticResult]:
        """Runs tactic detection across a batch of sample records.

        Args:
            records: List of sample dictionaries.
            text_field: Dictionary key containing the message text.
            id_field: Dictionary key containing sample ID.
            urls_field: Optional key or entity path for URLs.

        Returns:
            List of TacticResult objects.
        """
        results: List[TacticResult] = []
        for record in records:
            txt = record.get(text_field, "")
            sid = record.get(id_field)
            # Check URLs in entities dict or top-level field
            urls = None
            if "entities" in record and isinstance(record["entities"], dict):
                urls = record["entities"].get("urls")
            elif urls_field in record:
                urls = record.get(urls_field)

            res = self.detect(text=txt, sample_id=sid, urls=urls)
            results.append(res)
        return results
