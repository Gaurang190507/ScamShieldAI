"""ScamShield AI — Final Production Streamlit Console (Phase 18B).

AI-Powered Scam Investigation & Risk Analysis.
Multi-modal forensic investigation workbench delivering evidence-grounded risk assessments.

Run locally via:
    streamlit run app.py
or:
    streamlit run src/app/streamlit_app.py
"""

from datetime import datetime, timezone
import json
from pathlib import Path
import sys
from typing import Any, Dict, List, Optional

# Ensure project root is in sys.path
PROJECT_ROOT = Path(__file__).resolve().parents[2]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from PIL import Image
import streamlit as st

from src.app.schemas import InvestigationInput, InvestigationReport
from src.app.service import InvestigationService
from src.config.runtime_config import VERSION_METADATA, get_runtime_config
from src.ocr.environment import OCREnvironmentDetector


# =====================================================================
# 1. SERVICE SINGLETON & CACHING
# =====================================================================

@st.cache_resource
def get_investigation_service() -> InvestigationService:
    """Initializes and caches the singleton InvestigationService with pre-warmed models."""
    service = InvestigationService()
    try:
        service.warmup()
    except Exception:
        pass
    return service


# =====================================================================
# 2. SESSION STATE MANAGEMENT
# =====================================================================

def init_session_state() -> None:
    """Initializes in-memory session history and state containers."""
    if "investigation_history" not in st.session_state:
        st.session_state["investigation_history"] = []
    if "latest_report" not in st.session_state:
        st.session_state["latest_report"] = None
    if "active_mode" not in st.session_state:
        st.session_state["active_mode"] = "Quick Scan"


def record_case_history(report: InvestigationReport, preview_text: str) -> None:
    """Records an investigation summary into ephemeral in-memory session history."""
    history_entry = {
        "timestamp": datetime.now(timezone.utc).strftime("%H:%M:%S UTC"),
        "case_id": report.case_id,
        "input_type": report.input_type.replace("_", " ").title(),
        "preview": (preview_text[:50] + "...") if len(preview_text) > 50 else (preview_text or "N/A"),
        "verdict": report.assessment.get("status", "insufficient_evidence"),
        "evidence_level": report.assessment.get("evidence_level", "low").upper(),
        "latency_ms": round(report.timings_ms.get("total_ms", 0.0), 1),
        "report": report,
    }
    st.session_state["investigation_history"].insert(0, history_entry)
    st.session_state["latest_report"] = report


# =====================================================================
# 3. COMPONENT: HEADER & BRAND IDENTITY
# =====================================================================

def render_header() -> None:
    """Renders the top brand header and product positioning."""
    st.title("🛡️ ScamShield AI")
    st.markdown("#### **AI-Powered Scam Investigation & Risk Analysis**")
    st.caption(
        "Multi-Signal Forensic Investigation Workbench • Evidence-Grounded Detection • "
        "Deterministic Risk Aggregation • 100% Offline by Default"
    )
    st.markdown("---")


# =====================================================================
# 4. COMPONENT: FINAL ASSESSMENT CARD
# =====================================================================

def render_verdict_card(report: InvestigationReport, mode: str = "deep") -> None:
    """Renders prominent, calibrated assessment card based on Phase 8 verdict."""
    status = report.assessment.get("status", "insufficient_evidence").lower()
    evidence_level = report.assessment.get("evidence_level", "low").upper()
    consistency = report.assessment.get("signal_consistency", "unknown").replace("_", " ").title()

    if status == "likely_scam":
        banner_title = "🚨 VERDICT: LIKELY SCAM"
        banner_desc = (
            "Multiple corroborated indicators of fraudulent or coercive activity were isolated. "
            "High probability of deceptive intent."
        )
        st.error(f"### {banner_title}\n**Status**: Confirmed Risk Indicators | **Evidence Level**: {evidence_level}\n\n{banner_desc}")
    elif status == "likely_non_scam":
        banner_title = "✅ VERDICT: LIKELY NON-SCAM"
        banner_desc = (
            "Content aligns with legitimate communication patterns. No active exploitation, "
            "credential theft, or coercive tactics were detected."
        )
        st.success(f"### {banner_title}\n**Status**: Low Risk Identified | **Evidence Level**: {evidence_level}\n\n{banner_desc}")
    elif status == "mixed_signals":
        banner_title = "⚠️ VERDICT: MIXED SIGNALS"
        banner_desc = (
            "The available evidence contains contradictory or incomplete signals. "
            "Some suspicious patterns were isolated, but lack unanimous model corroboration. Proceed with caution."
        )
        st.warning(f"### {banner_title}\n**Status**: Suspicious / Inconclusive | **Evidence Level**: {evidence_level}\n\n{banner_desc}")
    else:
        banner_title = "ℹ️ VERDICT: INSUFFICIENT EVIDENCE"
        banner_desc = (
            "The submitted content does not contain sufficient signals to reach a definitive verdict. "
            "Please provide additional message text, links, or image context."
        )
        st.info(f"### {banner_title}\n**Status**: Inconclusive Content | **Evidence Level**: {evidence_level}\n\n{banner_desc}")

    if mode == "deep":
        col1, col2, col3, col4 = st.columns(4)
        col1.metric("Evidence Level", evidence_level)
        col2.metric("Signal Consistency", consistency)
        col3.metric("Input Modality", report.input_type.replace("_", " ").title())
        tot_lat = report.timings_ms.get("total_ms", 0.0)
        col4.metric("Pipeline Latency", f"{tot_lat:.1f} ms")


# =====================================================================
# 5. COMPONENT: RISK SIGNALS MATRIX
# =====================================================================

def extract_report_signals(report: Any) -> Dict[str, Any]:
    """Safely extracts key signals from an InvestigationReport or similar object.
    
    Guarantees no AttributeError whether .signals is absent, not a dict, or missing fields.
    Normalizes:
      - classifier_probability: Optional[float]
      - url_risk_score: Optional[float]
      - tactics: Optional[List[str]]
      - semantic_novelty_score: Optional[float]
    """
    out: Dict[str, Any] = {
        "classifier_probability": None,
        "url_risk_score": None,
        "tactics": None,
        "semantic_novelty_score": None,
    }
    if report is None:
        return out

    # 1. Safely inspect report.signals if present (dict or object)
    signals_val = getattr(report, "signals", None)
    if isinstance(signals_val, dict):
        out["classifier_probability"] = signals_val.get("classifier_probability")
        if out["classifier_probability"] is None and isinstance(signals_val.get("text_classifier"), dict):
            out["classifier_probability"] = signals_val["text_classifier"].get("probability")
        if out["classifier_probability"] is None and isinstance(signals_val.get("baseline_classifier"), dict):
            out["classifier_probability"] = signals_val["baseline_classifier"].get("probability")

        out["url_risk_score"] = signals_val.get("url_risk_score")
        if out["url_risk_score"] is None and isinstance(signals_val.get("url_analysis"), dict):
            out["url_risk_score"] = signals_val["url_analysis"].get("max_risk_score") or signals_val["url_analysis"].get("risk_score_max")

        if isinstance(signals_val.get("tactics"), dict):
            out["tactics"] = signals_val["tactics"].get("detected")

        out["semantic_novelty_score"] = signals_val.get("semantic_novelty_score")
        if out["semantic_novelty_score"] is None and isinstance(signals_val.get("semantic_similarity"), dict):
            out["semantic_novelty_score"] = signals_val["semantic_similarity"].get("novelty_score")
    elif signals_val is not None:
        out["classifier_probability"] = getattr(signals_val, "classifier_probability", None)
        out["url_risk_score"] = getattr(signals_val, "url_risk_score", None)
        out["tactics"] = getattr(signals_val, "tactics", None)
        out["semantic_novelty_score"] = getattr(signals_val, "semantic_novelty_score", None)

    # 2. Extract classifier probability from evidence if still None
    if out["classifier_probability"] is None:
        ev_by_source = getattr(report, "evidence_by_source", {})
        if isinstance(ev_by_source, dict):
            for item in ev_by_source.get("TEXT EVIDENCE", []):
                if isinstance(item, dict) and item.get("name") == "scam_probability":
                    out["classifier_probability"] = item.get("value")
                    break

    # 3. Extract URL risk score from findings/evidence if still None
    if out["url_risk_score"] is None:
        url_findings = getattr(report, "url_findings", [])
        if isinstance(url_findings, list) and url_findings:
            scores = [
                f.get("value", 0.0) for f in url_findings
                if isinstance(f, dict) and isinstance(f.get("value"), (int, float))
            ]
            if scores:
                out["url_risk_score"] = max(scores)
            else:
                out["url_risk_score"] = 0.0
        else:
            ev_by_source = getattr(report, "evidence_by_source", {})
            if isinstance(ev_by_source, dict) and ev_by_source.get("URL EVIDENCE"):
                scores = [
                    f.get("value", 0.0) for f in ev_by_source.get("URL EVIDENCE", [])
                    if isinstance(f, dict) and isinstance(f.get("value"), (int, float))
                ]
                if scores:
                    out["url_risk_score"] = max(scores)

    # 4. Extract tactics if still None
    if out["tactics"] is None:
        tactics_val = getattr(report, "detected_tactics", None)
        if isinstance(tactics_val, list):
            out["tactics"] = tactics_val

    # 5. Extract semantic novelty from context / evidence if still None
    if out["semantic_novelty_score"] is None:
        sem_ctx = getattr(report, "semantic_context", {})
        if isinstance(sem_ctx, dict):
            out["semantic_novelty_score"] = sem_ctx.get("novelty_score") or sem_ctx.get("semantic_novelty_score")
        if out["semantic_novelty_score"] is None:
            ev_by_source = getattr(report, "evidence_by_source", {})
            if isinstance(ev_by_source, dict):
                for item in ev_by_source.get("SEMANTIC EVIDENCE", []):
                    if isinstance(item, dict) and item.get("name") == "semantic_novelty_score":
                        out["semantic_novelty_score"] = item.get("value")
                        break

    return out


def render_risk_signals(report: InvestigationReport) -> None:
    """Renders high-level overview of isolated risk signals."""
    st.subheader("📊 Key Risk Signals")

    extracted = extract_report_signals(report)
    signals = []

    # 1. Classifier signal
    clf_prob = extracted.get("classifier_probability")
    if clf_prob is not None:
        if clf_prob >= 0.30:
            signals.append(("Text Classifier Signal", f"Scam probability score {clf_prob:.3f} exceeds threshold (0.30)", True))
        else:
            signals.append(("Text Classifier Signal", f"Score {clf_prob:.3f} below scam threshold", False))
    else:
        signals.append(("Text Classifier Signal", "Score: N/A (bypassed or unavailable)", False))

    # 2. URL signal
    url_score = extracted.get("url_risk_score")
    if url_score is not None:
        if url_score >= 0.40:
            signals.append(("URL Structure Signal", f"Structural risk score {url_score:.2f} indicates elevated risk", True))
        elif url_score > 0.0:
            signals.append(("URL Structure Signal", f"Minor URL heuristic flags (score {url_score:.2f})", False))
        elif getattr(report, "url_findings", None):
            signals.append(("URL Structure Signal", "Score 0.00 (clean URL structure)", False))
        else:
            signals.append(("URL Structure Signal", "Score: N/A (no URLs analyzed)", False))
    else:
        signals.append(("URL Structure Signal", "Score: N/A (no URLs analyzed)", False))

    # 3. Tactics signal
    tactics = extracted.get("tactics")
    if tactics:
        signals.append(("Behavioral Tactics", f"{len(tactics)} manipulative tactics detected ({', '.join(tactics[:3])})", True))
    elif tactics is not None:
        signals.append(("Behavioral Tactics", "No coercive behavioral tactics detected", False))
    else:
        signals.append(("Behavioral Tactics", "Tactics: N/A", False))

    # 4. Semantic novelty signal
    novelty = extracted.get("semantic_novelty_score")
    if novelty is not None:
        if novelty > 0.45:
            signals.append(("Pattern Novelty", f"Elevated novelty score ({novelty:.3f}) relative to reference baseline", True))
        else:
            signals.append(("Pattern Novelty", f"Recognized threat pattern (novelty score: {novelty:.3f})", False))
    else:
        signals.append(("Pattern Novelty", "Score: N/A (reference comparison unavailable)", False))

    cols = st.columns(len(signals) if signals else 1)
    for i, (name, desc, is_risk) in enumerate(signals):
        with cols[i]:
            if is_risk:
                st.error(f"**{name}**\n\n{desc}")
            else:
                st.success(f"**{name}**\n\n{desc}")


# =====================================================================
# 6. COMPONENT: SCAM TACTICS & EVIDENCE
# =====================================================================

def render_tactics_panel(report: InvestigationReport) -> None:
    """Renders detected social engineering tactics as cards with quoted evidence."""
    st.subheader("🎯 Manipulative Tactics Detected")

    tactics = report.detected_tactics
    if not tactics:
        st.info("No overt manipulative or social engineering tactics were identified in the content.")
        return

    st.write(f"**Active Tactic Flags ({len(tactics)}):** " + " ".join([f"`[{t.replace('_', ' ').title()}]`" for t in tactics]))

    # Display tactic evidence spans
    if report.tactic_spans:
        st.markdown("##### Grounded Tactic Quotes & Context")
        for span in report.tactic_spans:
            tactic_name = span.get("tactic", "").replace("_", " ").title()
            severity = span.get("severity", "medium").upper()
            matched = span.get("matched_text", "")
            reason = span.get("reason", "")
            
            with st.expander(f"📌 {tactic_name} — Severity: {severity}", expanded=True):
                st.markdown(f"**Matched Text**: *\"{matched}\"*")
                st.caption(f"**Forensic Context**: {reason}")


def render_evidence_panel(report: InvestigationReport) -> None:
    """Renders categorized evidence spans answering 'Why did the system say this?'."""
    st.subheader("🔎 Verbatim Evidence Spans")

    text_evidence = report.evidence_by_source.get("TEXT EVIDENCE", [])
    if text_evidence:
        for item in text_evidence:
            name = item.get("name", "Indicator")
            reason = item.get("reason", "")
            st.markdown(f"- **{name}**: {reason}")
    else:
        st.write("*No direct text evidence spans extracted.*")


# =====================================================================
# 7. COMPONENT: PASSIVE URL ANALYSIS
# =====================================================================

def render_url_analysis(report: InvestigationReport) -> None:
    """Renders passive URL structural inspection with explicit safety disclaimers."""
    st.subheader("🌐 Passive URL Structural Analysis")

    url_items = report.evidence_by_source.get("URL EVIDENCE", [])
    if not url_items:
        st.info("No URLs were extracted from this submission, or URL structures evaluated as clean.")
        return

    st.warning("🔒 **PASSIVE ANALYSIS ONLY**: ScamShield AI analyzes URL syntax, entropy, and domain structure offline. It NEVER visits, crawls, or opens suspect web links.")

    for item in url_items:
        name = item.get("name", "URL Trait")
        strength = item.get("strength", "info").upper()
        reason = item.get("reason", "")
        st.markdown(f"- **{name}** (`{strength}`): {reason}")


# =====================================================================
# 8. COMPONENT: SEMANTIC SIMILARITY & NOVELTY
# =====================================================================

def render_similarity_novelty(report: InvestigationReport) -> None:
    """Renders semantic memory search and cautious novelty assessment."""
    st.subheader("🧠 Semantic Memory & Pattern Novelty")

    col_sim, col_nov = st.columns(2)

    with col_sim:
        st.markdown("##### Reference Corpus Match")
        sim_items = report.evidence_by_source.get("SEMANTIC EVIDENCE", [])
        if sim_items:
            for item in sim_items:
                st.markdown(f"- **{item.get('name', '')}**: {item.get('reason', '')}")
        else:
            st.info("Semantic reference matching was neutral or disabled.")

    with col_nov:
        st.markdown("##### Emerging Threat Assessment")
        extracted = extract_report_signals(report)
        novelty_score = extracted.get("semantic_novelty_score")

        if novelty_score is not None:
            if novelty_score > 0.45:
                st.warning(
                    f"**Potentially Emerging Pattern** (Novelty: `{novelty_score:.3f}`)\n\n"
                    "The message combines suspicious behavioral tactics but exhibits low lexical "
                    "similarity to known reference cases. Caution advised."
                )
            else:
                st.success(
                    f"**Known / Similar Threat Pattern** (Novelty: `{novelty_score:.3f}`)\n\n"
                    "Content closely matches recognized scam narratives in the reference memory bank."
                )
        else:
            st.info("Pattern novelty evaluation not applicable for this input (N/A).")


# =====================================================================
# 9. COMPONENT: KNOWLEDGE EVIDENCE & AI EXPLANATION
# =====================================================================

def render_knowledge_and_explanation(report: InvestigationReport) -> None:
    """Renders authoritative RAG knowledge chunks and subordinate AI explanation."""
    st.subheader("📚 Verified Regulatory Guidance & Explanations")

    expl = report.explanation
    has_expl = report.explanation_available

    col_kb, col_ai = st.columns([1, 1])

    with col_kb:
        st.markdown("#### 1. Official Advisory Knowledge (RAG)")
        st.caption("Retrieved from offline regulatory database (RBI, FTC, CERT-In guidance)")
        kb_context = expl.get("knowledge_context", [])
        if kb_context:
            for kb in kb_context:
                claim = kb.get("claim", "") or kb.get("guidance", "")
                src_doc = kb.get("source_document", "") or kb.get("source_title", "Regulatory Bulletin")
                cit = kb.get("citation", "")
                st.markdown(f"📖 **{src_doc}** (`{cit}`):\n> {claim}")
        else:
            st.write("*No direct regulatory bulletins were cited for this specific case pattern.*")

    with col_ai:
        st.markdown("#### 2. Synthesized Case Explanation")
        st.caption("AI-generated plain language summary (subordinate to authoritative detection)")

        if has_expl:
            summary = expl.get("summary", "Summary unavailable.")
            st.markdown(f"**Investigation Summary:**\n\n{summary}")

            observed = expl.get("observed_evidence", [])
            if observed:
                st.markdown("**Key Observations:**")
                for obs in observed[:3]:
                    txt = obs.get("evidence", "") or obs.get("description", "")
                    cit = obs.get("citation", "")
                    st.markdown(f"- {txt} (`{cit}`)")
        else:
            st.warning("⚠️ **AI Explanation Unavailable**")
            fallback_sum = expl.get("summary", "Deterministic investigation results preserved.")
            st.info(f"Fallback Summary: {fallback_sum}")


# =====================================================================
# 10. COMPONENT: RECOMMENDED ACTION
# =====================================================================

def render_recommended_actions(report: InvestigationReport) -> None:
    """Renders conservative, actionable incident guidance based on risk."""
    st.subheader("🛡️ Recommended User Actions")

    status = report.assessment.get("status", "insufficient_evidence").lower()

    if status == "likely_scam":
        st.error(
            "1. **DO NOT** click any links, open attachments, or call provided phone numbers.\n"
            "2. **NEVER share OTPs**, UPI PINs, passwords, or net-banking credentials.\n"
            "3. **Verify Directly**: Contact the claimed organization via their official phone number from their authentic website.\n"
            "4. **Financial Action**: If you already transferred funds, immediately call your bank's fraud helpline and report to national cybercrime authorities."
        )
    elif status == "mixed_signals":
        st.warning(
            "1. **Exercise High Caution**: Do not immediately comply with requests in this message.\n"
            "2. **Independent Verification**: Independently check your account through the official mobile banking app or web portal.\n"
            "3. **Do not use contact numbers** provided within the suspicious message."
        )
    elif status == "likely_non_scam":
        st.success(
            "1. No overt fraudulent indicators were identified.\n"
            "2. **Standard Hygiene**: Always verify that URLs match official domains before entering credentials.\n"
            "3. *Note*: ScamShield AI evaluates known threats; standard caution is always recommended."
        )
    else:
        st.info(
            "1. Insufficient data to determine threat status.\n"
            "2. If this message requests urgent payments or credentials, treat it with caution."
        )


# =====================================================================
# 11. COMPONENT: TECHNICAL DETAILS & AUDIT TRAIL
# =====================================================================

def render_technical_details(report: InvestigationReport) -> None:
    """Renders expandable forensic technical details and export controls."""
    with st.expander("🔬 Technical Details & Forensic Audit Trail", expanded=False):
        tab_json, tab_timings, tab_audit = st.tabs(["Case JSON", "Pipeline Latencies", "Model Provenance"])

        with tab_json:
            st.json(report.to_dict())

        with tab_timings:
            st.markdown("##### Execution Timings (ms)")
            st.table(report.timings_ms)

        with tab_audit:
            st.markdown("##### System & Version Metadata")
            st.json({
                "audit": report.audit,
                "version_metadata": report.version_metadata,
            })

    col_d1, col_d2 = st.columns(2)
    with col_d1:
        st.download_button(
            "📥 Download Case Report (Markdown)",
            data=report.to_markdown(),
            file_name=f"{report.case_id}_report.md",
            mime="text/markdown",
            use_container_width=True,
        )
    with col_d2:
        st.download_button(
            "📥 Download Full Case JSON",
            data=json.dumps(report.to_dict(), indent=2),
            file_name=f"{report.case_id}_case.json",
            mime="application/json",
            use_container_width=True,
        )


# =====================================================================
# 12. WORKFLOW 1: QUICK SCAN
# =====================================================================

def render_quick_scan(service: InvestigationService, cfg) -> None:
    """Renders the streamlined Quick Scan workflow for everyday users."""
    st.subheader("⚡ Quick Scam Scan")
    st.markdown("Paste a suspicious SMS, WhatsApp message, email excerpt, or suspect link to get an immediate risk assessment.")

    # Preset sample selector for easy demonstration
    preset_choice = st.selectbox(
        "Try an Example Scenario (Optional):",
        [
            "-- Custom Input --",
            "Example 1: Urgent Bank KYC Phishing (Scam)",
            "Example 2: Routine Amazon Delivery OTP (Legitimate)",
            "Example 3: Institutional SBI Bank Portal (Clean URL)",
            "Example 4: Suspicious IP Address Link (Suspicious URL)",
        ],
    )

    preset_texts = {
        "Example 1: Urgent Bank KYC Phishing (Scam)": (
            "URGENT: Your HDFC bank account is suspended due to pending KYC verification. "
            "Update immediately at http://hdfc-kyc-update.com/login to avoid permanent block.",
            "",
        ),
        "Example 2: Routine Amazon Delivery OTP (Legitimate)": (
            "Amazon: Your package will be delivered today by agent Rajesh. "
            "Please share OTP 4821 with the delivery driver at your doorstep.",
            "",
        ),
        "Example 3: Institutional SBI Bank Portal (Clean URL)": (
            "",
            "https://www.onlinesbi.sbi/",
        ),
        "Example 4: Suspicious IP Address Link (Suspicious URL)": (
            "",
            "http://192.168.1.100/secure-banking/login.php",
        ),
    }

    default_text = preset_texts[preset_choice][0] if preset_choice in preset_texts else ""
    default_url = preset_texts[preset_choice][1] if preset_choice in preset_texts else ""

    input_text = st.text_area(
        "Suspicious Message Text",
        value=default_text,
        placeholder="Paste text here...",
        height=110,
    )
    input_url = st.text_input(
        "Suspicious Link / URL (Optional)",
        value=default_url,
        placeholder="e.g. https://suspicious-site.xyz/login",
    )

    if st.button("🚀 Analyze Now", type="primary", use_container_width=True):
        if not input_text.strip() and not input_url.strip():
            st.warning("Please enter text or a URL to analyze.")
            return

        with st.spinner("Analyzing threat signals..."):
            inv_input = InvestigationInput(
                text=input_text.strip(),
                url=input_url.strip(),
                provider_name="mock",
            )
            report = service.investigate(inv_input)
            preview = input_text.strip() or input_url.strip()
            record_case_history(report, preview)

    # Render results if available
    latest: Optional[InvestigationReport] = st.session_state.get("latest_report")
    if latest is not None:
        st.divider()
        render_verdict_card(latest, mode="quick")
        render_risk_signals(latest)
        render_recommended_actions(latest)


# =====================================================================
# 13. WORKFLOW 2: DEEP INVESTIGATION
# =====================================================================

def render_deep_investigation(service: InvestigationService, cfg, provider_choice: str, top_k: int) -> None:
    """Renders the comprehensive Deep Investigation workflow for forensic analysis."""
    st.subheader("🔬 Deep Forensic Investigation")
    st.markdown("Perform multi-signal forensic analysis across machine learning models, heuristic tactics, passive URL indicators, and semantic memory.")

    col1, col2 = st.columns([3, 2])
    with col1:
        input_text = st.text_area(
            "Message Content / Communications Text",
            placeholder="Paste suspicious SMS, email, WhatsApp message, or transcript...",
            height=140,
        )
    with col2:
        input_url = st.text_input(
            "Suspect Website / Link URL (Optional)",
            placeholder="e.g. http://192.168.1.50/secure/bank.php",
            help="Passive structural analysis only. ScamShield NEVER visits suspect links.",
        )
        st.caption("ℹ️ **Analysis Guarantee**: Zero external network requests during multi-signal detection.")

    if st.button("🔎 Run Full Investigation", type="primary", use_container_width=True):
        if not input_text.strip() and not input_url.strip():
            st.warning("Please provide message text or a URL for deep investigation.")
            return

        with st.spinner("Executing full forensic investigation across 11 stages..."):
            inv_input = InvestigationInput(
                text=input_text.strip(),
                url=input_url.strip(),
                provider_name=provider_choice,
                top_k=top_k,
            )
            report = service.investigate(inv_input)
            preview = input_text.strip() or input_url.strip()
            record_case_history(report, preview)

    # Render results
    latest: Optional[InvestigationReport] = st.session_state.get("latest_report")
    if latest is not None:
        st.divider()
        render_verdict_card(latest, mode="deep")
        st.divider()
        render_risk_signals(latest)
        st.divider()
        render_tactics_panel(latest)
        st.divider()
        render_evidence_panel(latest)
        st.divider()
        render_url_analysis(latest)
        st.divider()
        render_similarity_novelty(latest)
        st.divider()
        render_knowledge_and_explanation(latest)
        st.divider()
        render_recommended_actions(latest)
        st.divider()
        render_technical_details(latest)


# =====================================================================
# 14. WORKFLOW 3: SCREENSHOT SCAN
# =====================================================================

def render_screenshot_scan(service: InvestigationService, cfg, provider_choice: str, top_k: int) -> None:
    """Renders the dedicated Screenshot Investigation workflow."""
    st.subheader("📸 Screenshot Investigation")
    st.markdown("Upload screenshots of suspicious SMS, chat apps, or emails for OCR and visual analysis.")

    # Check native OCR environment status
    ocr_env = OCREnvironmentDetector.inspect()

    if not ocr_env.get("available", False):
        st.info(
            "ℹ️ **OCR Infrastructure Notice**: Native Tesseract OCR is unconfigured or not installed on this host. "
            "ScamShield AI will safely use graceful visual fallback without crashing."
        )
    else:
        st.success(f"🟢 **Native OCR Available**: Tesseract engine active ({ocr_env.get('binary_path', 'system PATH')})")

    col_upload, col_view = st.columns([1, 1])

    with col_upload:
        uploaded_file = st.file_uploader(
            "Choose Image File",
            type=["png", "jpg", "jpeg", "webp"],
            help="Supported formats: PNG, JPG, JPEG, WEBP (Max 10 MB).",
        )

    with col_view:
        if uploaded_file is not None:
            try:
                img = Image.open(uploaded_file)
                st.image(img, caption=f"Uploaded: {uploaded_file.name}", use_container_width=True)
            except Exception as e:
                st.error(f"Could not preview image: {e}")

    if st.button("🔍 Investigate Screenshot", type="primary", use_container_width=True):
        if uploaded_file is None:
            st.warning("Please upload an image file to investigate.")
            return

        img_bytes = uploaded_file.getvalue()
        img_name = uploaded_file.name

        with st.spinner("Extracting visual features and OCR text..."):
            inv_input = InvestigationInput(
                image_bytes=img_bytes,
                image_filename=img_name,
                provider_name=provider_choice,
                top_k=top_k,
            )
            report = service.investigate(inv_input)
            record_case_history(report, f"Screenshot: {img_name}")

    # Render results
    latest: Optional[InvestigationReport] = st.session_state.get("latest_report")
    if latest is not None and "image" in latest.input_type:
        st.divider()
        st.subheader("📝 Extracted OCR Content")
        if latest.ocr_text:
            st.code(latest.ocr_text, language="text")
        else:
            st.caption("*No optical text was extracted from this image (engine unavailable or image contains no legible text).*")

        render_verdict_card(latest, mode="deep")
        st.divider()
        render_risk_signals(latest)
        st.divider()
        render_tactics_panel(latest)
        st.divider()
        render_evidence_panel(latest)
        st.divider()
        render_recommended_actions(latest)
        st.divider()
        render_technical_details(latest)


# =====================================================================
# 15. WORKFLOW 4: INVESTIGATION HISTORY
# =====================================================================

def render_history_panel() -> None:
    """Renders the in-memory investigation session history table."""
    st.subheader("📜 Investigation History (Current Session)")
    st.caption("Ephemeral session history stored strictly in volatile memory. No user content is written to disk.")

    history = st.session_state.get("investigation_history", [])

    if not history:
        st.info("No investigations have been executed in this session yet.")
        return

    col_btn, _ = st.columns([1, 4])
    with col_btn:
        if st.button("🗑️ Clear History", use_container_width=True):
            st.session_state["investigation_history"] = []
            st.session_state["latest_report"] = None
            st.rerun()

    # Render table
    table_data = []
    for h in history:
        table_data.append({
            "Time": h["timestamp"],
            "Case ID": h["case_id"],
            "Modality": h["input_type"],
            "Content Preview": h["preview"],
            "Verdict": h["verdict"].replace("_", " ").title(),
            "Evidence": h["evidence_level"],
            "Latency": f"{h['latency_ms']} ms",
        })

    st.dataframe(table_data, use_container_width=True)


# =====================================================================
# 16. MAIN APPLICATION ENTRY POINT
# =====================================================================

def main():
    """Main application loop coordinating tabs, workflows, and sidebar controls."""
    st.set_page_config(
        page_title="ScamShield AI — Scam Investigation Console",
        page_icon="🛡️",
        layout="wide",
        initial_sidebar_state="expanded",
    )

    init_session_state()
    render_header()

    service = get_investigation_service()
    cfg = get_runtime_config()

    # Sidebar: Global System Settings & Privacy
    with st.sidebar:
        st.header("⚙️ Configuration")
        provider_choice = st.selectbox(
            "Explanation Provider (Phase 10)",
            ["mock", "groq", "gemini"],
            index=0,
            help="Default 'mock' mode runs 100% offline with zero network requests.",
        )

        top_k = st.slider(
            "Knowledge Base Citations (Top-K)",
            min_value=1,
            max_value=5,
            value=cfg.DEFAULT_RAG_TOP_K,
        )

        st.divider()
        st.header("🔒 Privacy & Boundaries")
        if provider_choice == "mock":
            st.success("🟢 **Offline Mode Active**\nZero external network calls. All models run locally.")
        else:
            st.warning(f"🟡 **Live API Active ({provider_choice.upper()})**\nExternal LLM invoked for explanation text.")

        st.caption("🛡️ **Zero Disk Logging**: No user messages or uploaded screenshots are persisted.")
        st.divider()
        st.caption(f"ScamShield v{VERSION_METADATA.PROJECT_VERSION}")
        st.caption(f"Provenance: {VERSION_METADATA.PHASE_VERSION}")

    # Top-Level Mode Navigation
    mode_tab1, mode_tab2, mode_tab3, mode_tab4 = st.tabs([
        "⚡ Quick Scan",
        "🔬 Deep Investigation",
        "📸 Screenshot Scan",
        "📜 Case History",
    ])

    with mode_tab1:
        render_quick_scan(service, cfg)

    with mode_tab2:
        render_deep_investigation(service, cfg, provider_choice, top_k)

    with mode_tab3:
        render_screenshot_scan(service, cfg, provider_choice, top_k)

    with mode_tab4:
        render_history_panel()


if __name__ == "__main__":
    main()
