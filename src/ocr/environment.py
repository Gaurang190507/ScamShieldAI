"""Native OCR environment inspector for ScamShield AI Phase 17 (Fix #4).

Detects whether a local native Tesseract OCR binary is installed and operational.
Supports explicit configuration via TESSERACT_CMD environment variable or constructor override.
Never crashes, never fakes OCR output, and transparently distinguishes host binary
unavailability from OCR extraction failure.
"""

import os
from pathlib import Path
import shutil
from typing import Any, Dict, Optional


class OCREnvironmentDetector:
    """Detects and reports host OCR binary availability and version."""

    @classmethod
    def get_tesseract_cmd(cls) -> Optional[str]:
        """Resolves Tesseract command path from environment or system PATH."""
        env_cmd = os.environ.get("TESSERACT_CMD")
        if env_cmd:
            p = Path(env_cmd)
            if p.is_file():
                return str(p.resolve())
            return env_cmd  # Let pytesseract report explicit invalid path error

        which_cmd = shutil.which("tesseract")
        if which_cmd:
            return which_cmd

        # Common Windows standard install paths check
        win_paths = [
            r"C:\Program Files\Tesseract-OCR\tesseract.exe",
            r"C:\Program Files (x86)\Tesseract-OCR\tesseract.exe",
        ]
        for wp in win_paths:
            if Path(wp).is_file():
                return wp

        return None

    @classmethod
    def inspect(cls, custom_cmd: Optional[str] = None) -> Dict[str, Any]:
        """Inspects OCR environment status returning structured diagnostics."""
        cmd = custom_cmd or cls.get_tesseract_cmd()
        status: Dict[str, Any] = {
            "installed": False,
            "executable_path": cmd,
            "version": None,
            "status": "unavailable",
            "warning": None,
        }

        try:
            import pytesseract
        except ImportError:
            status["warning"] = "pytesseract library is not installed in the Python environment."
            return status

        if cmd:
            try:
                pytesseract.pytesseract.tesseract_cmd = cmd
                ver = pytesseract.get_tesseract_version()
                status["installed"] = True
                status["version"] = str(ver)
                status["status"] = "available"
                status["warning"] = None
                return status
            except Exception as e:
                status["warning"] = (
                    f"Configured Tesseract binary at '{cmd}' failed invocation: {e}"
                )
                status["status"] = "invalid_binary"
                return status

        status["warning"] = (
            "Native Tesseract OCR binary not found in system PATH or TESSERACT_CMD. "
            "Host-level OCR execution is unavailable. Pipeline will fall back gracefully."
        )
        return status
