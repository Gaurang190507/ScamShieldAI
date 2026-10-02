"""ScamShield AI — Deployment Health & Startup Diagnostics (Phase 18C).

Provides pre-flight system validation to ensure:
1. All critical model binaries and vectorizers are present on disk.
2. Semantic memory embeddings and reference metadata exist.
3. Operating environment and Python dependencies satisfy requirements.
4. Optical character recognition (OCR) engine status is detected transparently.
5. Directory structures and runtime configuration are healthy.
"""

import hashlib
import os
from pathlib import Path
import sys
from typing import Any, Dict, List, Tuple

PROJECT_ROOT = Path(__file__).resolve().parents[2]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from src.config.runtime_config import VERSION_METADATA, get_runtime_config
from src.ocr.environment import OCREnvironmentDetector

CANONICAL_ARTIFACTS = {
    "baseline_vectorizer": {
        "path": PROJECT_ROOT / "models" / "baseline" / "tfidf_vectorizer.joblib",
        "sha256": "a3c25ebaa90d0df69e80101cd8f6ac9e6b4c17c579a476da26a722881c60e1d5",
    },
    "baseline_classifier": {
        "path": PROJECT_ROOT / "models" / "baseline" / "logistic_regression.joblib",
        "sha256": "93fd14c652241e46583de4beb3f62546d78932b629d0b8e930808c2a4f8336e6",
    },
    "char_vectorizer": {
        "path": PROJECT_ROOT / "models" / "phase13" / "char_ngram" / "char_vectorizer.joblib",
        "sha256": "bd53f31398d015130a711c7657cf31fe13e952e749631b3147b89532b1b3f142",
    },
    "char_classifier": {
        "path": PROJECT_ROOT / "models" / "phase13" / "char_ngram" / "char_classifier.joblib",
        "sha256": "86021d25325eb27a989651a7da23f0c3c8a6f78df660bf64694d107a3ff281a3",
    },
    "reference_embeddings": {
        "path": PROJECT_ROOT / "data" / "semantic" / "reference" / "reference_embeddings.npy",
        "sha256": "f4ad641ae6d3a34502a7f71ceaca1322762d9852c348c4e36cb767da2790101b",
    },
}

REQUIRED_DIRECTORIES = [
    PROJECT_ROOT / "models",
    PROJECT_ROOT / "data",
    PROJECT_ROOT / "src",
]


class StartupValidator:
    """Pre-flight diagnostic validator for deployment and container health checks."""

    @staticmethod
    def verify_artifacts(compute_hashes: bool = False) -> Dict[str, Any]:
        """Verifies presence and optionally SHA-256 integrity of all canonical model artifacts."""
        results = {}
        all_passed = True

        for name, spec in CANONICAL_ARTIFACTS.items():
            path: Path = spec["path"]
            exists = path.exists()
            file_size_bytes = path.stat().st_size if exists else 0

            status = {
                "exists": exists,
                "path": str(path),
                "size_bytes": file_size_bytes,
                "hash_verified": None,
            }

            if not exists:
                all_passed = False
            elif compute_hashes:
                digest = hashlib.sha256(path.read_bytes()).hexdigest()
                expected = spec["sha256"]
                matches = digest == expected
                status["hash_verified"] = matches
                status["digest"] = digest
                if not matches:
                    all_passed = False

            results[name] = status

        return {
            "all_passed": all_passed,
            "artifacts": results,
        }

    @staticmethod
    def verify_directories() -> Dict[str, Any]:
        """Verifies presence of foundational directory paths."""
        results = {}
        all_passed = True
        for d in REQUIRED_DIRECTORIES:
            exists = d.exists() and d.is_dir()
            results[str(d.name)] = {"path": str(d), "exists": exists}
            if not exists:
                all_passed = False

        return {"all_passed": all_passed, "directories": results}

    @staticmethod
    def verify_environment() -> Dict[str, Any]:
        """Inspects Python version, OS platform, and OCR engine configuration."""
        ocr_inspection = OCREnvironmentDetector.inspect()
        py_ver = f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}"
        py_ok = sys.version_info.major == 3 and sys.version_info.minor >= 10

        return {
            "python_version": py_ver,
            "python_supported": py_ok,
            "platform": sys.platform,
            "ocr_status": ocr_inspection,
        }

    @classmethod
    def run_diagnostics(cls, compute_hashes: bool = False) -> Dict[str, Any]:
        """Runs complete pre-flight check suite and determines overall system health."""
        dir_res = cls.verify_directories()
        art_res = cls.verify_artifacts(compute_hashes=compute_hashes)
        env_res = cls.verify_environment()

        is_healthy = dir_res["all_passed"] and art_res["all_passed"] and env_res["python_supported"]

        status = "healthy" if is_healthy else "degraded"

        return {
            "status": status,
            "healthy": is_healthy,
            "directories": dir_res,
            "artifacts": art_res,
            "environment": env_res,
            "version": VERSION_METADATA.PROJECT_VERSION,
        }


def check_health() -> bool:
    """Convenience boolean health check for container liveness/readiness probes."""
    diag = StartupValidator.run_diagnostics(compute_hashes=False)
    return diag["healthy"]


if __name__ == "__main__":
    import pprint
    diag = StartupValidator.run_diagnostics(compute_hashes=True)
    pprint.pprint(diag)
    sys.exit(0 if diag["healthy"] else 1)
