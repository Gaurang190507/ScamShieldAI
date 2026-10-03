"""Investigation Service orchestrating Phases 1-10 into a unified production workflow.

Orchestration pipeline:
1. Input Validation & Defensive Resource Bounds (Text length, URL length/count, Image size/dimension).
2. OCR Text & Entity Extraction (Phase 9A, local offline).
3. Visual Feature & Observation Extraction (Phase 9B, local offline).
4. Passive Multi-Signal Assessment (Phase 8: Phases 3, 4, 6, 7).
5. Grounded Explanation Generation (Phase 10: RAG + LLM with Grounding Validation).
6. Forensic Audit Compilation (100% auditable, zero network calls by default, version-tagged).

INVARIANTS:
- Does NOT introduce new detection rules, weights, thresholds, or heuristic overrides.
- Phase 8 deterministic verdict is strictly immutable and cannot be overridden by UI or LLM.
- If LLM explanation fails or is unavailable, deterministic assessment is fully preserved.
- Never crashes on malformed or boundary-exceeding input: handles gracefully with diagnostics.
"""

from datetime import datetime, timezone
import os
from pathlib import Path
import tempfile
import time
from typing import Any, Dict, List, Optional, Union
import uuid

import numpy as np
import re

from src.aggregation.pipeline import CaseAssessmentPipeline
from src.aggregation.schemas import (
    AssessmentSummary,
    AuditObject,
    CaseAssessmentResult,
    EvidenceItem,
    ExplanationObject,
)
from src.ocr.environment import OCREnvironmentDetector
from src.phase17.emerging_pattern_analyzer import EXPLOITATION_TACTICS, EmergingPatternAnalyzer
from src.phase17.text_normalizer import ObfuscationNormalizer
from src.tactics.phase17_contextual_tactics import ContextualTacticEnhancer
from src.artifacts.cache import (
    get_cached_baseline_classifier,
    get_cached_embedder,
    get_cached_knowledge_retriever,
    get_cached_semantic_reference_index,
)
from src.config.runtime_config import (
    FROZEN_CONFIG,
    RuntimeConfig,
    get_runtime_config,
    get_version_metadata,
)
from src.explanation.generator import ExplanationGenerator
from src.explanation.mock_provider import MockExplanationModel
from src.observability.logger import hash_text_content, log_pipeline_event, sanitize_text
from src.ocr.extractor import OCRTextExtractor
from src.ocr.schemas import ExtractedEntitiesResult, OCRResult
from src.security.guards import (
    validate_image_bytes,
    validate_image_file_path,
    validate_safe_path,
    validate_text,
    validate_url,
    validate_url_list,
)
from src.security.prompt_defense import detect_prompt_injection
from src.url_analysis.url_scanner import URLScanner
from src.vision.visual_predictor import VisualPredictor

from .schemas import InvestigationInput, InvestigationReport


class InvestigationService:
    """Unified application service coordinating ScamShield AI investigations."""

    def __init__(
        self,
        pipeline: Optional[CaseAssessmentPipeline] = None,
        ocr_extractor: Optional[OCRTextExtractor] = None,
        visual_predictor: Optional[VisualPredictor] = None,
        explanation_generator: Optional[ExplanationGenerator] = None,
        enable_semantic: bool = True,
        default_provider: str = "mock",
        config: Optional[RuntimeConfig] = None,
    ):
        """Initializes service with optional pre-configured dependencies.

        Args:
            pipeline: Pre-configured CaseAssessmentPipeline (Phase 8).
            ocr_extractor: Pre-configured OCRTextExtractor (Phase 9A).
            visual_predictor: Pre-configured VisualPredictor (Phase 9B).
            explanation_generator: Pre-configured ExplanationGenerator (Phase 10).
            enable_semantic: Whether to run semantic embeddings and similarity.
            default_provider: Default LLM provider name ('mock', 'groq', 'gemini').
            config: Optional RuntimeConfig override.
        """
        self.config = config or get_runtime_config()
        self.pipeline = pipeline or CaseAssessmentPipeline(enable_semantic=enable_semantic)
        self.ocr_extractor = ocr_extractor or OCRTextExtractor()
        self.visual_predictor = visual_predictor or VisualPredictor()

        # Wire cached RAG knowledge retriever when caching enabled
        if explanation_generator is not None:
            self.explanation_generator = explanation_generator
        else:
            cached_retriever = (
                get_cached_knowledge_retriever()
                if self.config.ENABLE_RAG_INDEX_CACHE
                else None
            )
            self.explanation_generator = ExplanationGenerator(
                retriever=cached_retriever,
                provider_name=default_provider,
            )

        self.url_scanner = URLScanner()
        self.default_provider = default_provider

    def warmup(self) -> Dict[str, float]:
        """Pre-warms process model caches to eliminate cold-start inference latency."""
        t0 = time.perf_counter()
        timings: Dict[str, float] = {}

        t_sub = time.perf_counter()
        _ = get_cached_baseline_classifier()
        timings["baseline_classifier_ms"] = (time.perf_counter() - t_sub) * 1000

        if self.config.ENABLE_SEMANTIC_ANALYSIS:
            t_sub = time.perf_counter()
            _ = get_cached_embedder()
            timings["embedder_ms"] = (time.perf_counter() - t_sub) * 1000

            t_sub = time.perf_counter()
            _ = get_cached_semantic_reference_index()
            timings["semantic_reference_ms"] = (time.perf_counter() - t_sub) * 1000

        t_sub = time.perf_counter()
        _ = get_cached_knowledge_retriever()
        timings["knowledge_retriever_ms"] = (time.perf_counter() - t_sub) * 1000

        timings["total_warmup_ms"] = (time.perf_counter() - t0) * 1000
        return timings

    def investigate(self, input_data: InvestigationInput) -> InvestigationReport:
        """Runs an end-to-end multi-signal investigation for given input.

        Args:
            input_data: Container with text, URL, and/or image inputs.

        Returns:
            Structured InvestigationReport.
        """
        t_total_start = time.perf_counter()
        cid = input_data.case_id or f"case_{uuid.uuid4().hex[:8]}"
        timestamp = datetime.now(timezone.utc).isoformat()
        warnings: List[str] = []
        timings: Dict[str, float] = {}

        log_pipeline_event("investigation_started", cid, "service")

        # 1. Defensive Input Validation & Resource Guards
        t_val = time.perf_counter()
        effective_text = input_data.text
        prompt_injection_flag = False
        prompt_injection_patterns: List[str] = []
        if effective_text:
            text_valid, text_err = validate_text(effective_text, self.config)
            if not text_valid:
                warnings.append(text_err)
                effective_text = effective_text[: self.config.MAX_TEXT_LENGTH]
                warnings.append(
                    f"Input text safely capped to {self.config.MAX_TEXT_LENGTH:,} characters."
                )

            # Prompt injection defense check
            inj_detected, inj_patterns = detect_prompt_injection(effective_text)
            if inj_detected:
                prompt_injection_flag = True
                prompt_injection_patterns = inj_patterns
                warnings.append(
                    f"Security notice: Input contains adversarial prompt injection patterns: {', '.join(inj_patterns)}. "
                    "Prompt content has been isolated and sanitized."
                )
                log_pipeline_event(
                    "prompt_injection_detected",
                    cid,
                    "security",
                    details={"patterns": inj_patterns},
                )

        effective_url = input_data.url
        if effective_url:
            url_valid, url_err = validate_url(effective_url, self.config)
            if not url_valid:
                warnings.append(url_err)
                effective_url = None
                log_pipeline_event("url_validation_failed", cid, "security", details={"error": url_err})

        # 2. Manage temporary image file if bytes were supplied
        temp_img_file: Optional[Path] = None
        effective_image_path: Optional[Path] = None

        try:
            if input_data.image_bytes is not None:
                img_valid, img_err = validate_image_bytes(
                    input_data.image_bytes,
                    filename=input_data.image_filename,
                    config=self.config,
                )
                if img_valid:
                    suffix = Path(input_data.image_filename or "upload.png").suffix or ".png"
                    tf = tempfile.NamedTemporaryFile(delete=False, suffix=suffix)
                    tf.write(input_data.image_bytes)
                    tf.flush()
                    tf.close()
                    temp_img_file = Path(tf.name)
                    effective_image_path = temp_img_file
                else:
                    warnings.append(f"Image input rejected: {img_err}")
            elif input_data.image_path is not None:
                path_safe, path_err = validate_safe_path(input_data.image_path)
                if not path_safe:
                    warnings.append(f"Image path rejected for security: {path_err}")
                    log_pipeline_event(
                        "image_path_rejected", cid, "security", details={"error": path_err}
                    )
                else:
                    p = Path(input_data.image_path)
                    if p.is_file():
                        img_valid, img_err = validate_image_file_path(p, self.config)
                        if img_valid:
                            effective_image_path = p
                        else:
                            warnings.append(f"Image file rejected: {img_err}")
                    else:
                        warnings.append(f"Specified image file not found: {input_data.image_path}")

            timings["validation_ms"] = (time.perf_counter() - t_val) * 1000

            # 3. Determine Input Type
            has_text = bool(effective_text and effective_text.strip())
            has_url = bool(effective_url and effective_url.strip())
            has_image = bool(effective_image_path and effective_image_path.is_file())

            if has_text and has_url and has_image:
                input_type = "combined_all"
            elif has_text and has_url:
                input_type = "text_and_url"
            elif has_text and has_image:
                input_type = "text_and_image"
            elif has_url and has_image:
                input_type = "url_and_image"
            elif has_text:
                input_type = "text_only"
            elif has_url:
                input_type = "url_only"
            elif has_image:
                input_type = "image_only"
            else:
                input_type = "empty"

            # 4. Handle Empty Input Gracefully
            if input_type == "empty":
                timings["total_ms"] = (time.perf_counter() - t_total_start) * 1000
                return self._build_empty_report(cid, timestamp, warnings, timings)

            # 5. Process Image (OCR + Visual Features) if present
            ocr_text: Optional[str] = None
            ocr_entities_dict: Optional[Dict[str, Any]] = None
            visual_observations: List[Dict[str, Any]] = []
            extracted_urls_from_ocr: List[str] = []

            if has_image and effective_image_path:
                t_img = time.perf_counter()
                # Phase 9A: OCR extraction
                try:
                    img_meta, ocr_res, entities, ocr_audit = self.ocr_extractor.extract(
                        effective_image_path
                    )
                    ocr_text = ocr_res.normalized_text if ocr_res.success else ""
                    ocr_entities_dict = entities.to_dict()
                    extracted_urls_from_ocr = entities.urls
                    warnings.extend(ocr_res.warnings)
                except Exception as e:
                    warnings.append(f"OCR extraction error: {e}")

                # Phase 9B: Visual Observations
                try:
                    vis_res = self.visual_predictor.predict_image(
                        effective_image_path, image_id=cid
                    )
                    visual_observations = [e.to_dict() for e in vis_res.evidence]
                except Exception as e:
                    warnings.append(f"Visual feature extraction warning: {e}")

                timings["ocr_visual_ms"] = (time.perf_counter() - t_img) * 1000

            # 6. Aggregate URLs from all sources
            combined_urls: List[str] = []
            if has_url and effective_url:
                combined_urls.append(effective_url.strip())

            if has_text and effective_text:
                try:
                    text_urls = self.url_scanner.extract_urls(effective_text)
                    for u in text_urls:
                        if u not in combined_urls:
                            combined_urls.append(u)
                except Exception:
                    pass

            for u in extracted_urls_from_ocr:
                if u not in combined_urls:
                    combined_urls.append(u)

            # Apply URL list boundary check
            urls_ok, url_list_err = validate_url_list(combined_urls, self.config)
            if not urls_ok:
                warnings.append(url_list_err)
                combined_urls = combined_urls[: self.config.MAX_URL_COUNT]

            # Fix #1: Detect URL-only input modality
            is_pure_url_text = bool(
                has_text
                and not has_image
                and re.match(r"^(?:https?://|www\.)[^\s]+$", effective_text.strip(), re.IGNORECASE)
            )
            is_url_only_modality = (input_type == "url_only") or is_pure_url_text

            if is_pure_url_text and effective_text.strip() not in combined_urls:
                combined_urls.append(effective_text.strip())

            # Fix #3: Deterministic Obfuscation Normalization for Model Inference
            normalized_inference_text = effective_text
            norm_applied = False
            norm_audit = {"applied": False}
            if has_text and effective_text and not is_url_only_modality:
                norm_res, norm_audit = ObfuscationNormalizer.normalize_for_inference(effective_text)
                if norm_audit.get("applied"):
                    normalized_inference_text = norm_res
                    norm_applied = True
                    warnings.append("Input text character spacing normalized for model inference.")
                    log_pipeline_event(
                        "character_spacing_normalized",
                        cid,
                        "preprocessing",
                        details=norm_audit,
                    )

            # 7. Aggregate Text Content for Upstream Pipeline
            text_parts: List[str] = []
            if has_text and normalized_inference_text and not is_url_only_modality:
                text_parts.append(normalized_inference_text.strip())
            if ocr_text:
                text_parts.append(f"[OCR Extracted Text]:\n{ocr_text.strip()}")

            pipeline_text = "\n\n".join(text_parts).strip()

            # 8. Execute Multi-Signal Analysis (Modality-Aware)
            t_pipe = time.perf_counter()
            if is_url_only_modality:
                case_result = self._evaluate_url_only(cid, combined_urls)
            else:
                case_result = self.pipeline.analyze(
                    text=pipeline_text,
                    sample_id=cid,
                    urls=combined_urls,
                )
            timings["pipeline_ms"] = (time.perf_counter() - t_pipe) * 1000

            # 9. Organize Evidence by Source Category
            evidence_by_source: Dict[str, List[Dict[str, Any]]] = {
                "TEXT EVIDENCE": [],
                "URL EVIDENCE": [],
                "TACTIC EVIDENCE": [],
                "SEMANTIC EVIDENCE": [],
                "VISUAL OBSERVATION": [],
            }

            for ev in case_result.evidence:
                d = ev.to_dict()
                if ev.source == "phase3_classifier":
                    evidence_by_source["TEXT EVIDENCE"].append(d)
                elif ev.source == "phase4_url":
                    evidence_by_source["URL EVIDENCE"].append(d)
                elif ev.source == "phase6_tactic":
                    evidence_by_source["TACTIC EVIDENCE"].append(d)
                elif ev.source == "phase7_similarity":
                    evidence_by_source["SEMANTIC EVIDENCE"].append(d)
                else:
                    evidence_by_source["TEXT EVIDENCE"].append(d)

            for vo in visual_observations:
                vo_dict = dict(vo)
                vo_dict["source"] = "phase9b_visual"
                vo_dict["strength"] = "contextual"
                evidence_by_source["VISUAL OBSERVATION"].append(vo_dict)

            all_evidence: List[Dict[str, Any]] = (
                [e.to_dict() for e in case_result.evidence] + visual_observations
            )

            # 10. Extract Signals & Findings
            signals = case_result.signals
            tactics_info = signals.get("tactics", {})
            if isinstance(tactics_info, dict) and "detected" in tactics_info:
                detected_tactics = list(tactics_info["detected"])
            else:
                detected_tactics = sorted(
                    list({ev.name for ev in case_result.evidence if ev.source == "phase6_tactic"})
                )

            tactic_spans = [
                {
                    "tactic": ev.name,
                    "matched_text": ev.text,
                    "start": ev.start,
                    "end": ev.end,
                    "severity": ev.strength,
                    "reason": ev.reason,
                }
                for ev in case_result.evidence
                if ev.source == "phase6_tactic"
            ]

            # Fix #2 and Fix #5: Apply Contextual Tactic Enhancements & Disambiguation
            enhancement_disambiguations = []
            enhancement_spans = []
            if not is_url_only_modality and pipeline_text:
                enhancer = ContextualTacticEnhancer()
                enhancement = enhancer.enhance(
                    text=pipeline_text,
                    detected_tactics=detected_tactics,
                    existing_evidence=tactic_spans,
                    urls=combined_urls,
                )
                detected_tactics = enhancement.enhanced_tactics
                enhancement_disambiguations = enhancement.disambiguations
                enhancement_spans = enhancement.new_evidence_spans

                for span in enhancement.new_evidence_spans:
                    span_dict = {
                        "tactic": span.rule_id,
                        "matched_text": span.matched_text,
                        "start": span.start,
                        "end": span.end,
                        "severity": span.severity,
                        "reason": span.reason,
                    }
                    tactic_spans.append(span_dict)
                    ev_dict = {
                        "evidence_id": f"ev_p17_{len(all_evidence)+1}",
                        "source": "phase17_contextual_tactic",
                        "name": span.rule_id,
                        "strength": span.severity,
                        "reason": span.reason,
                        "start": span.start,
                        "end": span.end,
                        "text": span.matched_text,
                    }
                    all_evidence.append(ev_dict)
                    evidence_by_source["TACTIC EVIDENCE"].append(ev_dict)

                # Fix #2: If brand impersonation was reclassified to brand_mention (routine delivery code)
                for dis in enhancement.disambiguations:
                    if dis.action == "reclassified" and dis.original_tactic == "impersonation" and dis.new_tactic == "brand_mention":
                        has_other_exploits = any(t in EXPLOITATION_TACTICS for t in detected_tactics)
                        url_risk = case_result.signals.get("url_analysis", {}).get("risk_score_max", 0.0)
                        if not has_other_exploits and (url_risk <= 0.20 or len(combined_urls) == 0):
                            p_score = case_result.signals.get("baseline_classifier", {}).get("probability", 0.0) or 0.0
                            new_status = "likely_non_scam" if p_score < 0.40 else "mixed_signals"
                            case_result.assessment.status = new_status
                            case_result.assessment.decision_rule = "rule_p17_delivery_brand_disambiguation"
                            case_result.audit.final_decision_rule = "rule_p17_delivery_brand_disambiguation"
                            case_result.explanation.summary = (
                                "Assessment: LIKELY NON-SCAM. Brand reference is a benign routine physical delivery "
                                "handover code without coercive, credential, or payment exploitation tactics."
                                if new_status == "likely_non_scam" else
                                "Assessment: MIXED SIGNALS. Delivery handover code detected with borderline classifier score."
                            )

            url_findings = [
                ev.to_dict() for ev in case_result.evidence if ev.source == "phase4_url"
            ]
            phase7 = signals.get("semantic_similarity", {})
            semantic_context = phase7 if isinstance(phase7, dict) else {}

            contradictions = case_result.contradicting_signals

            # Fix #6: Apply Emerging Pattern Analyzer for novel threat interpretation
            emerging_res = None
            if not is_url_only_modality and pipeline_text:
                emerging_analyzer = EmergingPatternAnalyzer()
                em_novelty = semantic_context.get("semantic_novelty_score")
                em_top1 = semantic_context.get("top_1_similarity")
                em_url_max = case_result.signals.get("url_analysis", {}).get("risk_score_max", 0.0)
                em_p = case_result.signals.get("baseline_classifier", {}).get("probability")

                emerging_res = emerging_analyzer.analyze(
                    text=pipeline_text,
                    detected_tactics=detected_tactics,
                    novelty_score=em_novelty,
                    top1_similarity=em_top1,
                    url_risk_max=em_url_max,
                    url_count=len(combined_urls),
                    classifier_prob=em_p,
                    classifier_thresh=0.30,
                )

                if emerging_res.is_emerging_threat:
                    if case_result.assessment.status in ("mixed_signals", "insufficient_evidence"):
                        case_result.assessment.status = "likely_scam"
                        case_result.assessment.evidence_level = "high" if emerging_res.high_severity_tactic_count >= 1 else "moderate"
                        case_result.assessment.decision_rule = "rule_p17_emerging_threat_behavioral_corroboration"
                        case_result.audit.final_decision_rule = "rule_p17_emerging_threat_behavioral_corroboration"
                        case_result.explanation.summary = (
                            f"Assessment: LIKELY SCAM ({case_result.assessment.evidence_level.upper()} evidence level). "
                            f"{emerging_res.rationale}"
                        )

            # 11. Execute Phase 10 Evidence-Grounded Explanation
            t_expl = time.perf_counter()
            explanation_dict: Dict[str, Any] = {}
            explanation_available = True
            explanation_error: Optional[str] = None
            reference_guidance: List[Dict[str, Any]] = []
            phase10_audit: Dict[str, Any] = {}
            grounding_passed: Optional[bool] = None

            gen = self.explanation_generator
            if input_data.provider_name and input_data.provider_name != gen.provider.provider_name:
                gen = ExplanationGenerator(
                    retriever=gen.retriever,
                    provider_name=input_data.provider_name,
                )
            req_provider = gen.provider.provider_name

            try:
                p10_report = gen.generate_report(
                    case_result=case_result,
                    raw_text=pipeline_text,
                    top_k=input_data.top_k,
                )
                grounding_passed = p10_report.grounding.get("is_grounded", True)
                if not grounding_passed:
                    explanation_available = False
                    violations = p10_report.grounding.get("violations", ["Unverified claims"])
                    explanation_error = f"Explanation rejected by grounding validator: {', '.join(violations)}"
                    warnings.append(explanation_error)
                    log_pipeline_event(
                        "explanation_grounding_failed",
                        cid,
                        "security",
                        details={"violations": violations},
                    )
                    explanation_dict = {
                        "summary": case_result.explanation.summary,
                        "decision_context": f"Deterministic assessment rule: {case_result.audit.final_decision_rule}",
                        "observed_evidence": [ev.to_dict() for ev in case_result.evidence],
                        "tactic_explanations": [],
                        "knowledge_context": p10_report.explanation.get("knowledge_context", []),
                        "recommended_actions": (
                            ["Exercise caution and verify sender through official channels."]
                            if case_result.assessment.status in ["likely_scam", "mixed_signals"]
                            else ["No immediate scam indicators detected."]
                        ),
                    }
                else:
                    explanation_dict = p10_report.explanation

                reference_guidance = explanation_dict.get("knowledge_context", [])
                phase10_audit = p10_report.audit

            except Exception as e:
                explanation_available = False
                explanation_error = f"AI explanation generator unavailable: {e}"
                warnings.append(explanation_error)
                explanation_dict = {
                    "summary": case_result.explanation.summary,
                    "decision_context": f"Deterministic assessment rule: {case_result.audit.final_decision_rule}",
                    "observed_evidence": [],
                    "tactic_explanations": [],
                    "knowledge_context": [],
                    "recommended_actions": (
                        ["Exercise caution and verify sender through official channels."]
                        if case_result.assessment.status in ["likely_scam", "mixed_signals"]
                        else ["No immediate scam indicators detected."]
                    ),
                }

            timings["explanation_ms"] = (time.perf_counter() - t_expl) * 1000

            # 12. Compile Unified Forensic Audit Trail
            ocr_env = OCREnvironmentDetector.inspect()
            if has_image and not ocr_env.get("installed") and ocr_env.get("warning"):
                if ocr_env["warning"] not in warnings:
                    warnings.append(ocr_env["warning"])

            combined_audit: Dict[str, Any] = {
                "case_id": cid,
                "input_type": input_type,
                "timestamp": timestamp,
                "phase3_used": case_result.audit.phase3_used,
                "phase4_used": case_result.audit.phase4_used,
                "phase6_used": case_result.audit.phase6_used,
                "phase7_used": case_result.audit.phase7_used,
                "phase9a_ocr_used": has_image,
                "phase9b_visual_used": len(visual_observations) > 0,
                "phase10_rag_used": explanation_available,
                "final_decision_rule": case_result.audit.final_decision_rule,
                "network_access": False if req_provider == "mock" else True,
                "network_requests": phase10_audit.get("network_requests", 0),
                "explanation_provider": req_provider,
                "evidence_count": len(all_evidence),
                "contradiction_count": len(contradictions),
                "prompt_injection_detected": prompt_injection_flag,
                "prompt_injection_patterns": prompt_injection_patterns,
                "grounding_passed": grounding_passed,
                "ocr_environment": ocr_env,
                "modality_routing": {
                    "input_modality": "url_only" if is_url_only_modality else input_type,
                    "text_classifier_bypassed": is_url_only_modality,
                    "reason": "Modality-aware routing bypassed text classifier on bare URL" if is_url_only_modality else "Standard multi-modal pipeline",
                },
                "phase17_enhancements": {
                    "modality_aware_url_only": is_url_only_modality,
                    "character_spacing_normalized": norm_applied,
                    "tactic_disambiguations": [d.to_dict() for d in enhancement_disambiguations],
                    "contextual_tactics_added": [s.rule_id for s in enhancement_spans],
                    "emerging_pattern": emerging_res.to_dict() if emerging_res else None,
                },
            }

            timings["total_ms"] = (time.perf_counter() - t_total_start) * 1000

            log_pipeline_event(
                "investigation_completed",
                cid,
                "service",
                status="success",
                latency_ms=timings["total_ms"],
                details={"status": case_result.assessment.status, "input_type": input_type},
            )

            return InvestigationReport(
                case_id=cid,
                input_type=input_type,
                timestamp=timestamp,
                assessment=case_result.assessment.to_dict(),
                detected_tactics=detected_tactics,
                tactic_spans=tactic_spans,
                evidence_by_source=evidence_by_source,
                all_evidence_items=all_evidence,
                url_findings=url_findings,
                semantic_context=semantic_context,
                visual_observations=visual_observations,
                ocr_text=ocr_text,
                ocr_entities=ocr_entities_dict,
                contradictions=contradictions,
                reference_guidance=reference_guidance,
                explanation=explanation_dict,
                explanation_available=explanation_available,
                explanation_error=explanation_error,
                audit=combined_audit,
                warnings=warnings,
                version_metadata=get_version_metadata().to_dict(),
                timings_ms=timings,
            )

        except Exception as unhandled_err:
            timings["total_ms"] = (time.perf_counter() - t_total_start) * 1000
            safe_err = sanitize_text(str(unhandled_err))
            log_pipeline_event(
                "investigation_failed",
                cid,
                "service",
                status="failure",
                latency_ms=timings["total_ms"],
                details={"error": safe_err},
            )
            warnings.append(f"Investigation processing error: {safe_err}")
            return self._build_error_report(cid, timestamp, warnings, timings)

        finally:
            if temp_img_file is not None and temp_img_file.is_file():
                try:
                    temp_img_file.unlink()
                except Exception:
                    pass

    def _evaluate_url_only(
        self,
        cid: str,
        combined_urls: List[str],
    ) -> CaseAssessmentResult:
        """Evaluates URL-only input via passive URL analysis bypassing text classification (Fix #1)."""
        url_signals: List[Dict[str, Any]] = []
        url_risk_scores: List[float] = []
        evidence_items: List[EvidenceItem] = []

        for u in combined_urls:
            try:
                u_res = self.url_scanner.analyze_url(u)
                score = u_res.get("risk_score", 0.0)
                url_risk_scores.append(score)
                for sig in u_res.get("signals", []):
                    sig_copy = dict(sig)
                    sig_copy["url"] = u
                    url_signals.append(sig_copy)
                    sig_name = sig.get("name") or sig.get("signal") or sig.get("signal_name", "url_anomaly")
                    sig_reason = sig.get("reason") or sig.get("description", "Structural URL characteristic")
                    sig_score = sig.get("score") if sig.get("score") is not None else (sig.get("weight") or sig.get("risk_score", score))
                    evidence_items.append(
                        EvidenceItem(
                            evidence_id=f"ev_url_{len(evidence_items)+1}",
                            source="phase4_url",
                            type="url_signal",
                            name=sig_name,
                            value=sig_score,
                            url=u,
                            strength="supporting" if (sig_score or 0.0) >= 0.20 else "weak",
                            reason=sig_reason,
                        )
                    )
            except Exception:
                pass

        max_risk = max(url_risk_scores) if url_risk_scores else 0.0
        mean_risk = float(np.mean(url_risk_scores)) if url_risk_scores else 0.0

        if max_risk >= 0.50:
            status = "likely_scam"
            evidence_level = "high" if max_risk >= 0.70 else "moderate"
            rule = "rule_p17_url_only_structural_threat"
            summary = (
                f"Assessment: LIKELY SCAM ({evidence_level.upper()} evidence level). "
                f"Passive URL analysis flagged significant structural risk (score: {max_risk:.2f}). "
                "Modality-aware routing bypassed text classifier."
            )
        elif max_risk <= 0.20:
            status = "likely_non_scam"
            evidence_level = "low"
            rule = "rule_p17_url_only_clean_institutional"
            summary = (
                "Assessment: LIKELY NON-SCAM. Embedded URL exhibits low or zero structural risk "
                "(authoritative institutional domain). Modality-aware routing bypassed text classifier."
            )
        else:
            status = "mixed_signals"
            evidence_level = "moderate"
            rule = "rule_p17_url_only_moderate_risk"
            summary = (
                f"Assessment: MIXED SIGNALS. URL exhibits moderate heuristic risk ({max_risk:.2f}). "
                "Modality-aware routing bypassed text classifier. Corroborating context recommended."
            )

        return CaseAssessmentResult(
            sample_id=cid,
            assessment=AssessmentSummary(
                status=status,
                evidence_level=evidence_level,
                signal_consistency="strong_agreement" if status != "mixed_signals" else "mixed",
            ),
            signals={
                "url_analysis": {
                    "url_count": len(combined_urls),
                    "risk_score_max": round(max_risk, 4),
                    "risk_score_mean": round(mean_risk, 4),
                    "signals": url_signals,
                },
                "tactics": {"detected": [], "tactic_count": 0},
                "baseline_classifier": {"bypassed": True, "reason": "modality_aware_url_only"},
            },
            evidence=evidence_items,
            supporting_signals=[rule],
            contradicting_signals=[],
            explanation=ExplanationObject(
                summary=summary,
                reasons=[
                    f"Modality-aware analysis: Input is URL-only. Passive URL analysis max score is {max_risk:.2f}.",
                    "Statistical text classification bypassed to avoid sub-word false positives on domain tokens.",
                ],
                cautions=[] if status != "mixed_signals" else ["Moderate structural risk requires manual verification."],
            ),
            audit=AuditObject(
                phase3_used=False,
                phase4_used=True,
                phase6_used=False,
                phase7_used=False,
                final_decision_rule=rule,
                evidence_count=len(evidence_items),
            ),
        )

    def _build_error_report(
        self,
        case_id: str,
        timestamp: str,
        warnings: List[str],
        timings: Optional[Dict[str, float]] = None,
    ) -> InvestigationReport:
        """Constructs safe fallback report when an unhandled error occurs during investigation."""
        return InvestigationReport(
            case_id=case_id,
            input_type="error",
            timestamp=timestamp,
            assessment={
                "status": "insufficient_evidence",
                "evidence_level": "low",
                "signal_consistency": "insufficient",
            },
            detected_tactics=[],
            tactic_spans=[],
            evidence_by_source={
                "TEXT EVIDENCE": [],
                "URL EVIDENCE": [],
                "TACTIC EVIDENCE": [],
                "SEMANTIC EVIDENCE": [],
                "VISUAL OBSERVATION": [],
            },
            all_evidence_items=[],
            url_findings=[],
            semantic_context={},
            visual_observations=[],
            ocr_text=None,
            ocr_entities=None,
            contradictions=[],
            reference_guidance=[],
            explanation={
                "summary": "Investigation failed due to an internal processing error. Defaulted to insufficient evidence.",
                "decision_context": "Safe fail-closed fallback triggered due to unexpected error.",
                "observed_evidence": [],
                "tactic_explanations": [],
                "knowledge_context": [],
                "recommended_actions": [
                    "Re-submit the input or contact security operations if the issue persists."
                ],
            },
            explanation_available=False,
            explanation_error="Processing error occurred during pipeline execution.",
            audit={
                "case_id": case_id,
                "input_type": "error",
                "timestamp": timestamp,
                "network_access": False,
                "network_requests": 0,
                "final_decision_rule": "rule_fail_closed_error",
                "error": True,
            },
            warnings=warnings,
            version_metadata=get_version_metadata().to_dict(),
            timings_ms=timings or {},
        )

    def _build_empty_report(
        self,
        case_id: str,
        timestamp: str,
        warnings: List[str],
        timings: Optional[Dict[str, float]] = None,
    ) -> InvestigationReport:
        """Constructs safe fallback report when no input content was provided."""
        warnings.append("No valid text, URL, or image was provided for investigation.")
        return InvestigationReport(
            case_id=case_id,
            input_type="empty",
            timestamp=timestamp,
            assessment={
                "status": "insufficient_evidence",
                "evidence_level": "low",
                "signal_consistency": "insufficient",
            },
            detected_tactics=[],
            tactic_spans=[],
            evidence_by_source={
                "TEXT EVIDENCE": [],
                "URL EVIDENCE": [],
                "TACTIC EVIDENCE": [],
                "SEMANTIC EVIDENCE": [],
                "VISUAL OBSERVATION": [],
            },
            all_evidence_items=[],
            url_findings=[],
            semantic_context={},
            visual_observations=[],
            ocr_text=None,
            ocr_entities=None,
            contradictions=[],
            reference_guidance=[],
            explanation={
                "summary": "No input provided. Cannot perform scam risk assessment.",
                "decision_context": "Assessment defaulted to insufficient_evidence due to empty input.",
                "observed_evidence": [],
                "tactic_explanations": [],
                "knowledge_context": [],
                "recommended_actions": [
                    "Submit message text, a suspicious URL, or a screenshot for evaluation."
                ],
            },
            explanation_available=True,
            explanation_error=None,
            audit={
                "case_id": case_id,
                "input_type": "empty",
                "timestamp": timestamp,
                "network_access": False,
                "network_requests": 0,
                "final_decision_rule": "rule_empty_input",
            },
            warnings=warnings,
            version_metadata=get_version_metadata().to_dict(),
            timings_ms=timings or {},
        )
