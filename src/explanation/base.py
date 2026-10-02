"""Abstract base provider interface for ScamShield AI Phase 10 explanation models."""

from abc import ABC, abstractmethod
from typing import Any, Dict

from .schemas import ExplanationRequest, ExplanationResponse


class BaseExplanationModel(ABC):
    """Abstract interface defining provider-neutral explanation generation contract."""

    @abstractmethod
    def generate_explanation(self, request: ExplanationRequest) -> ExplanationResponse:
        """Generates a structured, evidence-grounded explanation from the request context.

        Args:
            request: Standardized ExplanationRequest containing deterministic findings and retrieved chunks.

        Returns:
            ExplanationResponse dataclass instance.
        """
        pass

    @property
    @abstractmethod
    def provider_name(self) -> str:
        """Returns the canonical provider name (e.g., 'mock', 'groq', 'gemini')."""
        pass
