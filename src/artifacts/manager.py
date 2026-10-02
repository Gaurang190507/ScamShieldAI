"""Artifact validation and secure loading layer for ScamShield AI.

Features:
- Validates artifact existence, file types, sizes, checksums, and metadata schemas.
- Raises structured, transparent exceptions on missing or incompatible artifacts:
    Artifact Name + Expected Version/Schema + Actual Problem.
- Zero network access: never attempts automatic downloading of replacement artifacts.
- Deterministic compatibility checks for scikit-learn, joblib, and NumPy artifacts.
"""

import hashlib
import json
import os
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple, Union

from src.config.runtime_config import FROZEN_CONFIG, VERSION_METADATA, get_runtime_config


class ArtifactError(Exception):
    """Base exception for artifact errors."""
    pass


class ArtifactNotFoundError(ArtifactError):
    """Raised when an expected artifact file does not exist on disk."""
    pass


class ArtifactCorruptedError(ArtifactError):
    """Raised when an artifact checksum or header validation fails."""
    pass


class ArtifactIncompatibleError(ArtifactError):
    """Raised when an artifact schema, dimension, or version is incompatible."""
    pass


# Authoritative known SHA-256 hashes for frozen release artifacts
FROZEN_ARTIFACT_CHECKSUMS: Dict[str, str] = {
    "baseline_vectorizer": "a3c25ebaa90d0df69e80101cd8f6ac9e6b4c17c579a476da26a722881c60e1d5",
    "baseline_classifier": "93fd14c652241e46583de4beb3f62546d78932b629d0b8e930808c2a4f8336e6",
    "char_vectorizer": "bd53f31398d015130a711c7657cf31fe13e952e749631b3147b89532b1b3f142",
    "char_classifier": "86021d25325eb27a989651a7da23f0c3c8a6f78df660bf64694d107a3ff281a3",
    "reference_embeddings": "f4ad641ae6d3a34502a7f71ceaca1322762d9852c348c4e36cb767da2790101b",
}


def compute_file_sha256(path: Union[str, Path]) -> str:
    """Computes SHA-256 hex digest of a local file."""
    h = hashlib.sha256()
    with open(path, "rb") as f:
        while chunk := f.read(65536):
            h.update(chunk)
    return h.hexdigest()


def validate_file_artifact(
    path: Union[str, Path],
    artifact_name: str,
    expected_extensions: Tuple[str, ...],
    min_size_bytes: int = 1,
    max_size_bytes: Optional[int] = None,
    expected_sha256: Optional[str] = None,
) -> Path:
    """Defensively validates a file artifact before loading.

    Args:
        path: File path on disk.
        artifact_name: Human-readable name of the artifact.
        expected_extensions: Allowed file extensions (e.g. ('.joblib',)).
        min_size_bytes: Minimum expected file size in bytes.
        max_size_bytes: Optional maximum allowed file size in bytes.
        expected_sha256: Optional expected SHA-256 hash.

    Returns:
        Resolved Path instance.

    Raises:
        ArtifactNotFoundError: If file does not exist.
        ArtifactIncompatibleError: If file extension or size is invalid.
        ArtifactCorruptedError: If checksum verification fails.
    """
    p = Path(path).resolve()

    if not p.exists():
        raise ArtifactNotFoundError(
            f"Artifact [{artifact_name}] not found. "
            f"Expected path: '{p}'. "
            f"Schema version: {VERSION_METADATA.SCHEMA_VERSION}. "
            f"Actual problem: file does not exist on disk."
        )

    if not p.is_file():
        raise ArtifactIncompatibleError(
            f"Artifact [{artifact_name}] is not a regular file. "
            f"Path: '{p}'. "
            f"Actual problem: target is a directory or special device."
        )

    if p.suffix.lower() not in [ext.lower() for ext in expected_extensions]:
        raise ArtifactIncompatibleError(
            f"Artifact [{artifact_name}] has invalid file extension. "
            f"Path: '{p}'. "
            f"Expected extension: {expected_extensions}, got '{p.suffix}'. "
            f"Actual problem: file extension mismatch."
        )

    file_size = p.stat().st_size
    if file_size < min_size_bytes:
        raise ArtifactCorruptedError(
            f"Artifact [{artifact_name}] is empty or corrupted. "
            f"Path: '{p}'. "
            f"Expected minimum size: {min_size_bytes} bytes, got {file_size} bytes."
        )

    if max_size_bytes is not None and file_size > max_size_bytes:
        raise ArtifactIncompatibleError(
            f"Artifact [{artifact_name}] exceeds maximum allowed size. "
            f"Path: '{p}'. "
            f"Max size: {max_size_bytes} bytes, got {file_size} bytes."
        )

    if expected_sha256 is not None:
        actual_sha256 = compute_file_sha256(p)
        if actual_sha256.lower() != expected_sha256.lower():
            raise ArtifactCorruptedError(
                f"Artifact [{artifact_name}] failed integrity checksum verification. "
                f"Path: '{p}'. "
                f"Expected SHA-256: '{expected_sha256}', actual: '{actual_sha256}'. "
                f"Actual problem: file hash mismatch indicates corruption or unauthorized modification."
            )

    return p


class ArtifactManager:
    """Central validator and loader for ScamShield AI model and data artifacts."""

    @classmethod
    def validate_baseline_artifacts(
        cls, model_dir: Optional[Union[str, Path]] = None, check_checksums: bool = False
    ) -> Dict[str, Path]:
        """Validates Phase 3 baseline classifier artifacts."""
        mdir = Path(model_dir) if model_dir else FROZEN_CONFIG.BASELINE_MODEL_DIR
        vec_path = validate_file_artifact(
            mdir / "tfidf_vectorizer.joblib",
            artifact_name="Phase 3 TF-IDF Vectorizer",
            expected_extensions=(".joblib",),
            expected_sha256=FROZEN_ARTIFACT_CHECKSUMS["baseline_vectorizer"] if check_checksums else None,
        )
        clf_path = validate_file_artifact(
            mdir / "logistic_regression.joblib",
            artifact_name="Phase 3 Logistic Regression Classifier",
            expected_extensions=(".joblib",),
            expected_sha256=FROZEN_ARTIFACT_CHECKSUMS["baseline_classifier"] if check_checksums else None,
        )
        meta_path = validate_file_artifact(
            mdir / "model_metadata.json",
            artifact_name="Phase 3 Model Metadata",
            expected_extensions=(".json",),
        )

        # Validate metadata schema
        try:
            with open(meta_path, "r", encoding="utf-8") as f:
                meta = json.load(f)
            if "selected_threshold" not in meta or "vocabulary_size" not in meta:
                raise ArtifactIncompatibleError(
                    f"Artifact [Phase 3 Model Metadata] missing required schema keys. "
                    f"Path: '{meta_path}'. Missing 'selected_threshold' or 'vocabulary_size'."
                )
        except json.JSONDecodeError as e:
            raise ArtifactCorruptedError(
                f"Artifact [Phase 3 Model Metadata] contains malformed JSON: {e}"
            )

        return {"vectorizer": vec_path, "classifier": clf_path, "metadata": meta_path}

    @classmethod
    def validate_phase13_char_artifacts(
        cls, model_dir: Optional[Union[str, Path]] = None, check_checksums: bool = False
    ) -> Dict[str, Path]:
        """Validates Phase 13 Model B (character n-gram) artifacts."""
        mdir = Path(model_dir) if model_dir else FROZEN_CONFIG.PHASE13_CHAR_NGRAM_DIR
        vec_path = validate_file_artifact(
            mdir / "char_vectorizer.joblib",
            artifact_name="Phase 13 Character Vectorizer",
            expected_extensions=(".joblib",),
            expected_sha256=FROZEN_ARTIFACT_CHECKSUMS["char_vectorizer"] if check_checksums else None,
        )
        clf_path = validate_file_artifact(
            mdir / "char_classifier.joblib",
            artifact_name="Phase 13 Character Classifier",
            expected_extensions=(".joblib",),
            expected_sha256=FROZEN_ARTIFACT_CHECKSUMS["char_classifier"] if check_checksums else None,
        )
        meta_path = validate_file_artifact(
            mdir / "metadata.json",
            artifact_name="Phase 13 Character Metadata",
            expected_extensions=(".json",),
        )

        try:
            with open(meta_path, "r", encoding="utf-8") as f:
                meta = json.load(f)
            if "threshold" not in meta or "vocabulary_size" not in meta:
                raise ArtifactIncompatibleError(
                    f"Artifact [Phase 13 Character Metadata] missing required keys. "
                    f"Path: '{meta_path}'."
                )
        except json.JSONDecodeError as e:
            raise ArtifactCorruptedError(
                f"Artifact [Phase 13 Character Metadata] contains malformed JSON: {e}"
            )

        return {"vectorizer": vec_path, "classifier": clf_path, "metadata": meta_path}

    @classmethod
    def validate_semantic_reference_artifacts(
        cls, ref_dir: Optional[Union[str, Path]] = None, check_checksums: bool = False
    ) -> Dict[str, Path]:
        """Validates Phase 7 semantic reference corpus artifacts."""
        rdir = Path(ref_dir) if ref_dir else FROZEN_CONFIG.SEMANTIC_REFERENCE_DIR
        emb_path = validate_file_artifact(
            rdir / "reference_embeddings.npy",
            artifact_name="Semantic Reference Embeddings",
            expected_extensions=(".npy",),
            min_size_bytes=1000,
            expected_sha256=FROZEN_ARTIFACT_CHECKSUMS["reference_embeddings"] if check_checksums else None,
        )
        items_path = validate_file_artifact(
            rdir / "reference_items.jsonl",
            artifact_name="Semantic Reference Items",
            expected_extensions=(".jsonl",),
            min_size_bytes=1000,
        )
        meta_path = validate_file_artifact(
            rdir / "reference_embeddings.meta.json",
            artifact_name="Semantic Reference Metadata",
            expected_extensions=(".json",),
        )

        try:
            with open(meta_path, "r", encoding="utf-8") as f:
                meta = json.load(f)
            dim = meta.get("dimension")
            if dim != FROZEN_CONFIG.EMBEDDING_DIMENSION:
                raise ArtifactIncompatibleError(
                    f"Artifact [Semantic Reference Metadata] dimension mismatch. "
                    f"Expected: {FROZEN_CONFIG.EMBEDDING_DIMENSION}, actual: {dim}."
                )
        except json.JSONDecodeError as e:
            raise ArtifactCorruptedError(
                f"Artifact [Semantic Reference Metadata] contains malformed JSON: {e}"
            )

        return {"embeddings": emb_path, "items": items_path, "metadata": meta_path}

    @classmethod
    def validate_knowledge_base_artifacts(
        cls, kb_dir: Optional[Union[str, Path]] = None
    ) -> List[Path]:
        """Validates Phase 10 regulatory knowledge base documents."""
        kdir = Path(kb_dir) if kb_dir else FROZEN_CONFIG.KNOWLEDGE_BASE_DIR
        if not kdir.exists() or not kdir.is_dir():
            raise ArtifactNotFoundError(
                f"Artifact [Knowledge Base Directory] not found. "
                f"Expected directory: '{kdir}'."
            )

        json_files = sorted(list(kdir.glob("**/*.json")))
        if not json_files:
            raise ArtifactNotFoundError(
                f"Artifact [Knowledge Base Documents] contains no JSON files in '{kdir}'."
            )

        return json_files
