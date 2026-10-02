"""Canonical data schemas for ScamShield AI Phase 9B Visual Scam Classification.

Defines structured objects for:
- VisualSampleRecord: Metadata, labels, provenance, and hashes for visual samples.
- VisualFeatures: Deterministic pixel and layout features extracted from image rasters.
- VisualEvidenceItem: Traceable, explainable observation extracted from visual features.
- VisualPredictionResult: Evaluation outcome from the visual-only classifier.
- CombinedPredictionResult: Multimodal synthesis comparing text vs. visual signals.
- VisualLeakageReport: Forensic verification certifying zero cross-split leakage.
"""

from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional


@dataclass
class VisualSampleRecord:
    """Metadata and annotation for a visual sample in the Phase 9B evaluation corpus."""

    image_id: str
    image_path: str
    label: str  # "scam", "non_scam"
    source_type: str  # "synthetic", "real"
    scenario: str  # e.g., "account_suspension", "delivery_notice", "qr_payment", "otp_alert"
    pattern_group_id: str  # Cluster ID for group-leakage partitioning
    paired_text_id: Optional[str] = None
    paired_layout_id: Optional[str] = None
    ground_truth_text: str = ""
    visual_notes: str = ""
    annotation_confidence: float = 1.0
    image_hash: str = ""  # SHA-256 raster hash
    perceptual_hash: str = ""  # 64-bit dHash / aHash string
    split: Optional[str] = None  # "train", "val", "test"

    def to_dict(self) -> Dict[str, Any]:
        """Serializes record to dictionary."""
        return asdict(self)


@dataclass
class VisualFeatures:
    """Deterministic, explainable visual and layout features extracted from image pixels."""

    # 1. Geometry
    width: int
    height: int
    aspect_ratio: float  # width / height

    # 2. Photometric & Luminance
    mean_brightness: float  # [0.0, 255.0]
    std_brightness: float  # Contrast metric
    entropy: float  # Shannon entropy of pixel intensity histogram
    whitespace_ratio: float  # Fraction of near-white background pixels (> 240)

    # 3. Chromatic / Color Distribution
    mean_red: float
    mean_green: float
    mean_blue: float
    red_ratio: float  # R / (R + G + B + 1e-5)
    mean_saturation: float  # Mean HSV saturation in [0.0, 1.0]
    color_variance: float  # Variance across RGB channels

    # 4. Edge & Structural Complexity
    edge_density: float  # Fraction of pixels with high spatial gradient magnitude
    top_luminance_ratio: float  # Mean brightness in top 20% / overall brightness
    bottom_luminance_ratio: float  # Mean brightness in bottom 20% / overall brightness
    horizontal_asymmetry: float  # Absolute difference between left and right half brightness

    # 5. Salient Layout Elements (Heuristic / Pixel morphology)
    header_banner_detected: bool  # Distinct contrasting top header band
    button_candidate_count: int  # Distinct button-like high-contrast rectangular regions
    qr_candidate_detected: bool  # Dense square high-contrast block in middle/lower area

    def to_dict(self) -> Dict[str, Any]:
        """Serializes features to dictionary."""
        return asdict(self)

    def to_feature_vector(self) -> List[float]:
        """Converts numerical features into an ordered vector for statistical classifiers."""
        return [
            float(self.width),
            float(self.height),
            float(self.aspect_ratio),
            float(self.mean_brightness),
            float(self.std_brightness),
            float(self.entropy),
            float(self.whitespace_ratio),
            float(self.mean_red),
            float(self.mean_green),
            float(self.mean_blue),
            float(self.red_ratio),
            float(self.mean_saturation),
            float(self.color_variance),
            float(self.edge_density),
            float(self.top_luminance_ratio),
            float(self.bottom_luminance_ratio),
            float(self.horizontal_asymmetry),
            1.0 if self.header_banner_detected else 0.0,
            float(self.button_candidate_count),
            1.0 if self.qr_candidate_detected else 0.0,
        ]

    @staticmethod
    def feature_names() -> List[str]:
        """Returns ordered list of feature names matching to_feature_vector."""
        return [
            "width",
            "height",
            "aspect_ratio",
            "mean_brightness",
            "std_brightness",
            "entropy",
            "whitespace_ratio",
            "mean_red",
            "mean_green",
            "mean_blue",
            "red_ratio",
            "mean_saturation",
            "color_variance",
            "edge_density",
            "top_luminance_ratio",
            "bottom_luminance_ratio",
            "horizontal_asymmetry",
            "header_banner_detected",
            "button_candidate_count",
            "qr_candidate_detected",
        ]


@dataclass
class VisualEvidenceItem:
    """Atomic explainable visual observation."""

    feature: str
    value: Any
    role: str  # "visual_observation", "contextual_signal"
    reason: str

    def to_dict(self) -> Dict[str, Any]:
        """Serializes evidence item to dictionary."""
        return asdict(self)


@dataclass
class VisualPredictionResult:
    """Structured output from visual scam classification."""

    image_id: str
    predicted_label: str  # "scam", "non_scam"
    probability: float  # Estimated probability of scam class
    threshold: float
    features: Dict[str, Any]
    evidence: List[VisualEvidenceItem] = field(default_factory=list)
    audit: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        """Serializes visual prediction to dictionary."""
        return {
            "image_id": self.image_id,
            "predicted_label": self.predicted_label,
            "probability": round(self.probability, 4),
            "threshold": round(self.threshold, 4),
            "features": self.features,
            "evidence": [e.to_dict() for e in self.evidence],
            "audit": self.audit,
        }


@dataclass
class CombinedPredictionResult:
    """Multimodal synthesis comparing text vs. visual signals."""

    image_id: str
    ground_truth_label: str
    scenario: str
    source_type: str
    text_prediction: Dict[str, Any]
    visual_prediction: Dict[str, Any]
    combined_prediction: Dict[str, Any]
    complementarity_category: str  # "visual_only_useful", "text_only_useful", "contradictory", "concordant_agreement"
    cautions: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        """Serializes multimodal prediction to dictionary."""
        return asdict(self)


@dataclass
class VisualLeakageReport:
    """Audit report certifying zero data leakage across visual dataset splits."""

    train_count: int
    val_count: int
    test_count: int
    exact_duplicate_overlap: int
    perceptual_duplicate_overlap: int
    pattern_group_overlap: int
    is_leakage_free: bool
    audit_notes: List[str] = field(default_factory=list)
    timestamp: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )

    def to_dict(self) -> Dict[str, Any]:
        """Serializes leakage report to dictionary."""
        return asdict(self)
