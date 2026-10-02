"""ScamShield AI — Phase 10 Explanation Layer Module.

Provides provider-neutral LLM abstraction, prompt engineering,
evidence grounding validation, and unified investigation report synthesis.
"""

from .base import BaseExplanationModel
from .gemini_provider import GeminiExplanationModel
from .generator import ExplanationGenerator
from .groq_provider import GroqExplanationModel
from .mock_provider import MockExplanationModel
from .prompts import SYSTEM_PROMPT, build_explanation_user_prompt
from .schemas import (
    ExplanationRequest,
    ExplanationResponse,
    GroundingValidationResult,
    KnowledgeContextItem,
    ObservedEvidenceItem,
    Phase10InvestigationReport,
    TacticExplanationItem,
)
from .validator import GroundingValidator

__all__ = [
    "BaseExplanationModel",
    "MockExplanationModel",
    "GroqExplanationModel",
    "GeminiExplanationModel",
    "GroundingValidator",
    "ExplanationGenerator",
    "SYSTEM_PROMPT",
    "build_explanation_user_prompt",
    "ExplanationRequest",
    "ExplanationResponse",
    "GroundingValidationResult",
    "Phase10InvestigationReport",
    "ObservedEvidenceItem",
    "TacticExplanationItem",
    "KnowledgeContextItem",
]
