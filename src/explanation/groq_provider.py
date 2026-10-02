"""Groq LLM explanation provider adapter for ScamShield AI Phase 10.

Requires:
- Environment variable `GROQ_API_KEY`.
- Network access (disabled during automated test execution).
"""

import json
import os
import urllib.request
import urllib.error
from typing import Any, Dict, Optional

from .base import BaseExplanationModel
from .prompts import SYSTEM_PROMPT, build_explanation_user_prompt
from .schemas import ExplanationRequest, ExplanationResponse


class GroqExplanationModel(BaseExplanationModel):
    """Provider adapter invoking Groq API (e.g., llama-3.3-70b-versatile)."""

    def __init__(
        self,
        api_key: Optional[str] = None,
        model_name: str = "llama-3.3-70b-versatile",
        temperature: float = 0.0,
    ):
        """Initializes Groq provider with optional explicit key or environment variable."""
        self._api_key = api_key or os.environ.get("GROQ_API_KEY")
        self.model_name = model_name
        self.temperature = temperature

    @property
    def provider_name(self) -> str:
        return "groq"

    def generate_explanation(self, request: ExplanationRequest) -> ExplanationResponse:
        """Invokes Groq API to generate structured explanation."""
        if not self._api_key:
            raise ValueError(
                "GROQ_API_KEY environment variable is not set. "
                "Set GROQ_API_KEY or use MockExplanationModel for offline operation."
            )

        user_content = build_explanation_user_prompt(request)
        payload = {
            "model": self.model_name,
            "messages": [
                {"role": "system", "content": SYSTEM_PROMPT},
                {"role": "user", "content": user_content},
            ],
            "temperature": self.temperature,
            "response_format": {"type": "json_object"},
        }

        req = urllib.request.Request(
            "https://api.groq.com/openai/v1/chat/completions",
            data=json.dumps(payload).encode("utf-8"),
            headers={
                "Authorization": f"Bearer {self._api_key}",
                "Content-Type": "application/json",
            },
            method="POST",
        )

        try:
            with urllib.request.urlopen(req, timeout=30) as resp:
                raw_response = resp.read().decode("utf-8")
                resp_json = json.loads(raw_response)
                content_str = resp_json["choices"][0]["message"]["content"]
                parsed_dict = json.loads(content_str)
        except urllib.error.HTTPError as e:
            err_body = e.read().decode("utf-8", errors="replace")
            raise RuntimeError(f"Groq API error ({e.code}): {err_body}") from e
        except Exception as e:
            raise RuntimeError(f"Failed to invoke Groq API: {e}") from e

        return ExplanationResponse(
            summary=parsed_dict.get("summary", ""),
            decision_context=parsed_dict.get("decision_context", ""),
            observed_evidence=parsed_dict.get("observed_evidence", []),
            tactic_explanations=parsed_dict.get("tactic_explanations", []),
            knowledge_context=parsed_dict.get("knowledge_context", []),
            uncertainties=parsed_dict.get("uncertainties", []),
            recommended_action=parsed_dict.get("recommended_action", ""),
            confidence_statement=parsed_dict.get("confidence_statement", ""),
        )
