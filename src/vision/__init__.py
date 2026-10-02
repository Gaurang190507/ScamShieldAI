"""ScamShield AI — Phase 9B: Visual Scam Classification Module.

Provides deterministic, explainable, and offline visual feature extraction,
supervised statistical classification, evidence synthesis, and data leakage audit.
"""

from .dataset_generator import build_synthetic_dataset
from .evidence import extract_visual_evidence
from .evaluate_visual import run_phase9b_experiments
from .image_features import extract_visual_features
from .leakage import (
    audit_visual_leakage,
    compute_dhash,
    compute_image_sha256,
    hamming_distance,
    partition_by_group,
)
from .schemas import (
    CombinedPredictionResult,
    VisualEvidenceItem,
    VisualFeatures,
    VisualLeakageReport,
    VisualPredictionResult,
    VisualSampleRecord,
)
from .visual_classifier import VisualScamClassifier
from .visual_predictor import VisualPredictor

__all__ = [
    "VisualSampleRecord",
    "VisualFeatures",
    "VisualEvidenceItem",
    "VisualPredictionResult",
    "CombinedPredictionResult",
    "VisualLeakageReport",
    "extract_visual_features",
    "extract_visual_evidence",
    "VisualScamClassifier",
    "VisualPredictor",
    "compute_image_sha256",
    "compute_dhash",
    "hamming_distance",
    "partition_by_group",
    "audit_visual_leakage",
    "run_phase9b_experiments",
    "build_synthetic_dataset",
]
