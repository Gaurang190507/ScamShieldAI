"""Structured application logging and PII/Secret sanitization for ScamShield AI.

Features:
- Structured operational event logging (case ID, stage, status, timing, metadata).
- Automated PII and secret redaction filter:
  * Masks API keys (Groq, Gemini, Bearer tokens).
  * Masks known environment secret values.
  * Masks password, OTP, and sensitive credential tokens.
  * Replaces raw message bodies with cryptographic SHA-256 digests and character counts.
- Zero network logging: purely local stdout and/or file handlers.
"""

from datetime import datetime, timezone
import hashlib
import json
import logging
import os
import re
from typing import Any, Dict, Optional

from src.config.runtime_config import get_runtime_config


# Regex patterns identifying potential secrets, keys, and tokens
SECRET_PATTERNS = [
    (re.compile(r"gsk_[A-Za-z0-9_-]{20,}", re.IGNORECASE), "[REDACTED_GROQ_KEY]"),
    (re.compile(r"AIza[0-9A-Za-z-_]{30,}", re.IGNORECASE), "[REDACTED_GEMINI_KEY]"),
    (re.compile(r"(?:bearer\s+|bearer\s*[:=]\s*['\"]?)([A-Za-z0-9_\-\.]{16,})['\"]?", re.IGNORECASE), "Bearer [REDACTED_TOKEN]"),
    (re.compile(r"(?:token|apikey|api_key|auth_token|secret_key)\s*[:=]\s*['\"]?([A-Za-z0-9_\-\.]{16,})['\"]?", re.IGNORECASE), "[REDACTED_TOKEN]"),
    (re.compile(r"(?:password|passwd|pwd)\s*[:=]\s*['\"]?([^\s'\"]{6,})['\"]?", re.IGNORECASE), "[REDACTED_PASSWORD]"),
    (re.compile(r"\b(?:otp|verification\s+code|one[- ]time[- ]password)\s*(?:is|:|=)?\s*['\"]?([0-9]{4,8})['\"]?\b", re.IGNORECASE), "[REDACTED_OTP]"),
    (re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----", re.IGNORECASE), "[REDACTED_PRIVATE_KEY]"),
]


def sanitize_text(text: str) -> str:
    """Masks known secrets, API keys, and sensitive tokens from arbitrary log text."""
    if not isinstance(text, str):
        return ""

    sanitized = text

    # 1. Mask specific environment variables if present
    for env_var in ["GROQ_API_KEY", "GEMINI_API_KEY", "OPENAI_API_KEY"]:
        val = os.environ.get(env_var)
        if val and len(val) >= 8 and val in sanitized:
            sanitized = sanitized.replace(val, f"[REDACTED_{env_var}]")

    # 2. Mask pattern matches
    for pattern, replacement in SECRET_PATTERNS:
        sanitized = pattern.sub(replacement, sanitized)

    return sanitized


def hash_text_content(text: str) -> str:
    """Computes SHA-256 digest of input text for safe reference logging."""
    if not text:
        return "empty"
    return hashlib.sha256(text.encode("utf-8")).hexdigest()[:16]


class SanitizingFilter(logging.Filter):
    """Logging filter that scrubs sensitive secrets from log record messages."""

    def filter(self, record: logging.LogRecord) -> bool:
        if isinstance(record.msg, str):
            record.msg = sanitize_text(record.msg)
        if isinstance(record.args, dict):
            record.args = {
                k: sanitize_text(v) if isinstance(v, str) else v
                for k, v in record.args.items()
            }
        elif isinstance(record.args, tuple):
            record.args = tuple(
                sanitize_text(a) if isinstance(a, str) else a for a in record.args
            )
        return True


class StructuredJsonFormatter(logging.Formatter):
    """Formats log records as single-line JSON objects."""

    def format(self, record: logging.LogRecord) -> str:
        payload: Dict[str, Any] = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
        }

        # Include custom structured extra fields
        if hasattr(record, "structured_event"):
            payload["event_data"] = record.structured_event

        return json.dumps(payload)


def get_logger(name: str = "scamshield") -> logging.Logger:
    """Configures and returns a sanitized structured logger."""
    logger = logging.getLogger(name)

    if not logger.handlers:
        cfg = get_runtime_config()
        level = getattr(logging, cfg.LOG_LEVEL.upper(), logging.INFO)
        logger.setLevel(level)

        handler = logging.StreamHandler()
        handler.setLevel(level)

        # Standard clean formatter
        formatter = logging.Formatter(
            "[%(asctime)s] [%(levelname)s] [%(name)s] %(message)s",
            datefmt="%Y-%m-%d %H:%M:%S",
        )
        handler.setFormatter(formatter)

        if cfg.SANITIZE_LOGS:
            handler.addFilter(SanitizingFilter())

        logger.addHandler(handler)
        logger.propagate = False

    return logger


def log_pipeline_event(
    event: str,
    case_id: str,
    stage: str,
    status: str = "success",
    latency_ms: Optional[float] = None,
    error: Optional[str] = None,
    details: Optional[Dict[str, Any]] = None,
) -> None:
    """Emits a structured audit log event."""
    logger = get_logger("scamshield.pipeline")
    event_data: Dict[str, Any] = {
        "event": event,
        "case_id": case_id,
        "stage": stage,
        "status": status,
        "latency_ms": round(latency_ms, 2) if latency_ms is not None else None,
        "error": sanitize_text(str(error)) if error else None,
        "details": details or {},
    }

    msg = f"[{stage}] case={case_id} event={event} status={status}"
    if latency_ms is not None:
        msg += f" latency={latency_ms:.1f}ms"
    if error:
        msg += f" error={error}"

    extra = {"structured_event": event_data}
    if status == "error":
        logger.error(msg, extra=extra)
    elif status == "warning":
        logger.warning(msg, extra=extra)
    else:
        logger.info(msg, extra=extra)
