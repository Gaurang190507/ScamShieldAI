"""Visual Predictor service for ScamShield AI Phase 9B.

Binds:
1. Local deterministic pixel feature extraction (VisualFeatures).
2. Forensic, transparent evidence item generation (VisualEvidenceItem).
3. Supervised statistical prediction (VisualScamClassifier).
4. Structured prediction result packaging (VisualPredictionResult).
"""

from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Union
from PIL import Image

from .evidence import extract_visual_evidence
from .image_features import extract_visual_features
from .schemas import VisualFeatures, VisualPredictionResult
from .visual_classifier import VisualScamClassifier


class VisualPredictor:
    """Predictor service generating visual risk scores and transparent evidence."""

    def __init__(self, classifier: Optional[VisualScamClassifier] = None):
        """Initializes predictor with a trained VisualScamClassifier."""
        self.classifier = classifier

    def predict_image(
        self,
        image_input: Union[Image.Image, Path, str],
        image_id: Optional[str] = None,
        threshold: Optional[float] = None,
    ) -> VisualPredictionResult:
        """Evaluates an image visually, extracting features, evidence, and prediction.

        Args:
            image_input: PIL Image or path to image file.
            image_id: Optional identifier string.
            threshold: Optional override decision threshold.

        Returns:
            VisualPredictionResult dataclass.
        """
        # Resolve PIL image
        if isinstance(image_input, (str, Path)):
            img_path = Path(image_input)
            sample_id = image_id or img_path.stem
            with Image.open(img_path) as img:
                pil_image = img.convert("RGB")
        elif isinstance(image_input, Image.Image):
            pil_image = image_input.convert("RGB")
            sample_id = image_id or "image_sample"
        else:
            raise TypeError(f"Unsupported image input type: {type(image_input)}")

        # 1. Deterministic feature extraction
        features = extract_visual_features(pil_image)

        # 2. Transparent evidence item extraction
        evidence_items = extract_visual_evidence(features)

        # 3. Classifier inference
        effective_threshold = threshold
        if self.classifier is not None and self.classifier.is_fitted:
            prob = self.classifier.predict_proba(features)
            label, _ = self.classifier.predict(features, threshold=threshold)
            effective_threshold = (
                threshold if threshold is not None else self.classifier.threshold
            )
        else:
            # Fallback heuristic if classifier not fitted
            prob = 0.50
            label = "non_scam"
            effective_threshold = threshold or 0.50

        # 4. Forensic audit trail
        audit_trail: Dict[str, Any] = {
            "processed_at": datetime.now(timezone.utc).isoformat(),
            "offline_execution": True,
            "network_requests": 0,
            "external_models": 0,
            "dimensions": {"width": features.width, "height": features.height},
        }

        return VisualPredictionResult(
            image_id=sample_id,
            predicted_label=label,
            probability=prob,
            threshold=effective_threshold,
            features=features.to_dict(),
            evidence=evidence_items,
            audit=audit_trail,
        )
