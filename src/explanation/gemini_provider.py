"""Gemini LLM explanation provider adapter for ScamShield AI Phase 10.

Requires:
- Environment variable `GEMINI_API_KEY`.
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


class GeminiExplanationModel(BaseExplanationModel):
    """Provider adapter invoking Google Gemini API."""

    def __init__(
        self,
        api_key: Optional[str] = None,
        model_name: str = "gemini-1.5-flash",
        temperature: float = 0.0,
    ):
        """Initializes Gemini provider with optional explicit key or environment variable."""
        self._api_key = api_key or os.environ.get("GEMINI_API_KEY")
        self.model_name = model_name
        self.temperature = temperature

    @property
    def provider_name(self) -> str:
        return "gemini"

    def generate_explanation(self, request: ExplanationRequest) -> ExplanationResponse:
        """Invokes Gemini API to generate structured explanation."""
        if not self._api_key:
            raise ValueError(
                "GEMINI_API_KEY environment variable is not set. "
                "Set GEMINI_API_KEY or use MockExplanationModel for offline operation."
            )

        user_content = build_explanation_user_prompt(request)
        url = (
            f"https://generativelanguage.googleapis.com/v1beta/models/"
            f"{self.model_name}:generateContent?key={self._api_key}"
        )

        payload = {
            "system_instruction": {"parts": [{"text": SYSTEM_PROMPT}]},
            "contents": [{"parts": [{"text": user_content}]}],
            "generationConfig": {
                "temperature": self.temperature,
                "response_mime_type": "application/json",
            },
        }

        req = urllib.request.Request(
            url,
            data=json.dumps(payload).encode("utf-8"),
            headers={"Content-Type": "application/json"},
            method="POST",
        )

        try:
            with urllib.request.urlopen(req, timeout=30) as resp:
                raw_response = resp.read().decode("utf-8")
                resp_json = json.loads(raw_response)
                candidate = resp_json["candidates"][0]
                content_str = candidate["content"]["parts"][0]["text"]
                parsed_dict = json.loads(content_str)
        except urllib.error.HTTPError as e:
            err_body = e.read().decode("utf-8", errors="replace")
            raise RuntimeError(f"Gemini API error ({e.code}): {err_body}") from e
        except Exception as e:
            raise RuntimeError(f"Failed to invoke Gemini API: {e}") from e

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
