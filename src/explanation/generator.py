"""Explanation generation orchestrator for ScamShield AI Phase 10.

Coordinates:
1. Knowledge retrieval via KnowledgeRetriever.
2. Standardized ExplanationRequest construction from Phase 8 CaseAssessmentResult.
3. Provider invocation (Mock, Groq, Gemini).
4. Post-generation grounding validation.
5. Compilation of unified Phase10InvestigationReport with extended forensic audit trail.
"""

from datetime import datetime, timezone
import os
from typing import Any, Dict, List, Optional, Union

from src.aggregation.schemas import CaseAssessmentResult
from src.rag.retriever import KnowledgeRetriever
from .base import BaseExplanationModel
from .gemini_provider import GeminiExplanationModel
from .groq_provider import GroqExplanationModel
from .mock_provider import MockExplanationModel
from .schemas import (
    ExplanationRequest,
    ExplanationResponse,
    GroundingValidationResult,
    Phase10InvestigationReport,
)
from .validator import GroundingValidator


class ExplanationGenerator:
    """End-to-end service producing evidence-grounded, validated explanation reports."""

    def __init__(
        self,
        retriever: Optional[KnowledgeRetriever] = None,
        provider: Optional[BaseExplanationModel] = None,
        validator: Optional[GroundingValidator] = None,
        provider_name: Optional[str] = None,
    ):
        """Initializes generator with configured components."""
        self.retriever = retriever or KnowledgeRetriever()
        self.validator = validator or GroundingValidator()

        if provider is not None:
            self.provider = provider
        else:
            # Resolve provider from argument or environment variable
            p_name = (provider_name or os.environ.get("EXPLANATION_PROVIDER", "mock")).lower().strip()
            if p_name == "groq":
                self.provider = GroqExplanationModel()
            elif p_name == "gemini":
                self.provider = GeminiExplanationModel()
            else:
                self.provider = MockExplanationModel()

    def generate_report(
        self,
        case_result: CaseAssessmentResult,
        raw_text: Optional[str] = None,
        top_k: int = 3,
    ) -> Phase10InvestigationReport:
        """Executes full Phase 10 workflow: Retrieval -> Explanation -> Validation -> Report.

        Args:
            case_result: Phase 8 CaseAssessmentResult instance.
            raw_text: Optional untrusted raw user input.
            top_k: Number of reference passages to retrieve.

        Returns:
            Phase10InvestigationReport dataclass instance.
        """
        # 1. Retrieve relevant knowledge chunks
        retrieval_res = self.retriever.retrieve(case_result=case_result, top_k=top_k)

        # 2. Extract structured signals from case_result
        signals = case_result.signals
        phase6 = signals.get("phase6_tactics", {})
        tactics = phase6.get("detected_tactics", []) if isinstance(phase6, dict) else []

        phase4 = signals.get("phase4_url", {})
        url_signals = phase4.get("signals", []) if isinstance(phase4, dict) else []

        phase7 = signals.get("phase7_semantic", {})

        # Build evidence items with explicit citation tags
        evidence_dicts: List[Dict[str, Any]] = []
        for idx, ev in enumerate(case_result.evidence, start=1):
            e_dict = ev.to_dict()
            e_dict["citation_id"] = f"[CASE:{ev.evidence_id}]"
            evidence_dicts.append(e_dict)

        # Format retrieved knowledge chunks
        kb_dicts: List[Dict[str, Any]] = [c.to_dict() for c in retrieval_res.retrieved_chunks]

        # 3. Build structured ExplanationRequest
        request = ExplanationRequest(
            case_id=case_result.sample_id or "unnamed_case",
            deterministic_result=case_result.assessment.to_dict(),
            tactics=tactics,
            url_findings=url_signals,
            semantic_findings=phase7 if isinstance(phase7, dict) else {},
            contradictions=case_result.contradicting_signals,
            evidence=evidence_dicts,
            retrieved_knowledge=kb_dicts,
            raw_text=raw_text,
        )

        # 4. Generate structured explanation via provider
        response = self.provider.generate_explanation(request)

        # 5. Run Grounding Validator
        validation = self.validator.validate(request=request, response=response)

        # 6. Build extended forensic audit trail (preserving Phase 8 compliance)
        audit_trail: Dict[str, Any] = {
            "explanation_provider": self.provider.provider_name,
            "prompt_version": "1.0.0",
            "retrieval_method": retrieval_res.retrieval_method,
            "retrieved_document_ids": sorted(list({c.document_id for c in retrieval_res.retrieved_chunks})),
            "retrieved_chunk_ids": [c.chunk_id for c in retrieval_res.retrieved_chunks],
            "retrieval_scores": [c.similarity_score for c in retrieval_res.retrieved_chunks],
            "grounding_status": validation.status,
            "validation_passed": validation.is_grounded,
            "validation_errors": validation.errors,
            "validation_warnings": validation.warnings,
            "network_requests": 0 if self.provider.provider_name == "mock" else 1,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }

        return Phase10InvestigationReport(
            case_id=request.case_id,
            deterministic_assessment=case_result.assessment.to_dict(),
            explanation=response.to_dict(),
            grounding=validation.to_dict(),
            audit=audit_trail,
        )
