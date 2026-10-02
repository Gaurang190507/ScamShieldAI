"""Data models and schemas for ScamShield AI Phase 11 Investigation Application.

Defines:
- InvestigationInput: Container for text, URL, screenshot/image, and investigation parameters.
- InvestigationReport: Comprehensive structured output consolidating:
  * Phase 8 Multi-Signal Deterministic Assessment
  * Source-categorized Evidence (Text, URL, Tactic, Semantic, Visual)
  * Phase 10 Evidence-Grounded Explanation (with citations)
  * OCR & Visual Observation details (if image provided)
  * Forensic Audit Trail
"""

from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Union
import uuid


@dataclass
class InvestigationInput:
    """Unified container for user-supplied investigation inputs."""

    text: Optional[str] = None
    url: Optional[str] = None
    image_path: Optional[Union[str, Path]] = None
    image_bytes: Optional[bytes] = None
    image_filename: Optional[str] = None
    case_id: Optional[str] = None
    provider_name: Optional[str] = None
    top_k: int = 3
    enable_semantic: bool = True

    def __post_init__(self):
        if not self.case_id:
            self.case_id = f"case_{uuid.uuid4().hex[:8]}"


@dataclass
class InvestigationReport:
    """Comprehensive case-level investigation report consolidating Phases 1-10."""

    case_id: str
    input_type: str  # "text_only", "url_only", "image_only", "text_and_url", "text_and_image", "url_and_image", "combined_all", "empty"
    timestamp: str
    assessment: Dict[str, Any]  # status, evidence_level, signal_consistency
    detected_tactics: List[str] = field(default_factory=list)
    tactic_spans: List[Dict[str, Any]] = field(default_factory=list)
    evidence_by_source: Dict[str, List[Dict[str, Any]]] = field(default_factory=dict)
    all_evidence_items: List[Dict[str, Any]] = field(default_factory=list)
    url_findings: List[Dict[str, Any]] = field(default_factory=list)
    semantic_context: Dict[str, Any] = field(default_factory=dict)
    visual_observations: List[Dict[str, Any]] = field(default_factory=list)
    ocr_text: Optional[str] = None
    ocr_entities: Optional[Dict[str, Any]] = None
    contradictions: List[str] = field(default_factory=list)
    reference_guidance: List[Dict[str, Any]] = field(default_factory=list)
    explanation: Dict[str, Any] = field(default_factory=dict)
    explanation_available: bool = True
    explanation_error: Optional[str] = None
    audit: Dict[str, Any] = field(default_factory=dict)
    warnings: List[str] = field(default_factory=list)
    version_metadata: Dict[str, Any] = field(default_factory=dict)
    timings_ms: Dict[str, float] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        """Serializes investigation report to standard JSON dictionary."""
        return asdict(self)

    def to_markdown(self) -> str:
        """Renders investigation report as human-readable Markdown."""
        status = self.assessment.get("status", "unknown").upper()
        ev_level = self.assessment.get("evidence_level", "unknown").upper()
        consistency = self.assessment.get("signal_consistency", "unknown")

        md = [
            f"# ScamShield AI — Case Investigation Report",
            f"**Case ID:** `{self.case_id}`  ",
            f"**Timestamp:** {self.timestamp}  ",
            f"**Input Type:** `{self.input_type}`  ",
            "",
            "## 1. Deterministic Case Assessment",
            f"- **Verdict / Status:** **`{status}`**",
            f"- **Evidence Level:** `{ev_level}`",
            f"- **Signal Consistency:** `{consistency}`",
            "",
            "## 2. Multi-Signal Evidence Summary",
        ]

        # Grouped evidence
        for group, items in self.evidence_by_source.items():
            if items:
                md.append(f"### {group} ({len(items)} items)")
                for item in items:
                    name = item.get("name") or item.get("feature") or "signal"
                    reason = item.get("reason", "")
                    strength = item.get("strength") or item.get("role", "")
                    val = item.get("value")
                    val_str = f" = {val}" if val is not None else ""
                    md.append(f"- **{name}**{val_str} *[{strength}]*: {reason}")
                md.append("")

        if self.ocr_text:
            md.extend([
                "## 3. Extracted OCR Content",
                "```text",
                self.ocr_text,
                "```",
                "",
            ])

        md.extend([
            "## 4. Evidence-Grounded Explanation (Phase 10)",
        ])

        if self.explanation_available:
            summary = self.explanation.get("summary", "No summary generated.")
            decision_ctx = self.explanation.get("decision_context", "")
            actions = self.explanation.get("recommended_actions", [])

            md.extend([
                f"**Summary:** {summary}",
                "",
                f"**Decision Context:** {decision_ctx}",
                "",
            ])

            obs = self.explanation.get("observed_evidence", [])
            if obs:
                md.append("### What ScamShield Observed")
                for o in obs:
                    text_val = o.get("evidence", "") or o.get("description", "")
                    raw_cit = o.get("citation", "")
                    cit = f" `{raw_cit}`" if raw_cit else ""
                    md.append(f"- {text_val}{cit}")
                md.append("")

            kb_ctx = self.explanation.get("knowledge_context", [])
            if kb_ctx:
                md.append("### Relevant Reference Guidance")
                for k in kb_ctx:
                    claim_val = k.get("claim", "") or k.get("guidance", "")
                    raw_cit = k.get("citation", "")
                    cit = f" `{raw_cit}`" if raw_cit else ""
                    src_doc = k.get("source_document", "") or k.get("source_title", "")
                    src = f" *(Source: {src_doc})*" if src_doc else ""
                    md.append(f"- {claim_val}{cit}{src}")
                md.append("")

            if actions:
                md.append("### Recommended Next Steps")
                for act in actions:
                    md.append(f"- {act}")
                md.append("")
        else:
            md.extend([
                "> **AI Explanation Unavailable**: Fallback to deterministic assessment summary.",
                f"> Reason: {self.explanation_error or 'Provider execution skipped or failed.'}",
                "",
                f"**Deterministic Summary:** {self.explanation.get('summary', 'Assessment completed based on deterministic rules.')}",
                "",
            ])

        md.extend([
            "## 5. Forensic Audit Trail",
            f"- **Network Requests:** {self.audit.get('network_requests', 0)}",
            f"- **Offline Execution:** {self.audit.get('network_access', False) is False}",
            f"- **Decision Rule:** `{self.audit.get('final_decision_rule', 'N/A')}`",
            f"- **Components Executed:** Phase 3 ({self.audit.get('phase3_used')}), Phase 4 ({self.audit.get('phase4_used')}), Phase 6 ({self.audit.get('phase6_used')}), Phase 7 ({self.audit.get('phase7_used')})",
        ])

        if self.version_metadata or self.timings_ms:
            md.extend([
                "",
                "## 6. Provenance & Performance Telemetry",
            ])
            if self.version_metadata:
                md.append(f"- **Project Version:** `{self.version_metadata.get('project_version', '1.0.0')}` ({self.version_metadata.get('phase_version', 'Phase 14')})")
                md.append(f"- **Schema Version:** `{self.version_metadata.get('schema_version', '1.0.0')}`")
            if self.timings_ms:
                tot = self.timings_ms.get("total_ms", 0.0)
                md.append(f"- **Total Latency:** `{tot:.1f} ms`")
                sub_timings = [f"{k}={v:.1f}ms" for k, v in self.timings_ms.items() if k != "total_ms"]
                if sub_timings:
                    md.append(f"- **Stage Breakdown:** {', '.join(sub_timings)}")

        return "\n".join(md)
