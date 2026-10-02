"""Standard prediction and model schemas for ScamShield AI Phase 13."""

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional


@dataclass
class Phase13Prediction:
    """Standardized prediction result for Phase 13 experimental models."""

    sample_id: Optional[str]
    model_name: str
    label: str  # "scam" or "non_scam"
    probability: float  # scam probability in [0.0, 1.0]
    threshold: float  # decision threshold
    scam_probability: float
    non_scam_probability: float
    features_used: List[str] = field(default_factory=list)
    signals_detected: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        """Serializes prediction to standard dictionary format."""
        return {
            "sample_id": self.sample_id,
            "model_name": self.model_name,
            "label": self.label,
            "probability": round(self.probability, 4),
            "threshold": round(self.threshold, 4),
            "scam_probability": round(self.scam_probability, 4),
            "non_scam_probability": round(self.non_scam_probability, 4),
            "features_used": self.features_used,
            "signals_detected": self.signals_detected,
        }
