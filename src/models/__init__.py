"""ScamShield AI ML modeling package."""

from .baseline_classifier import BaselineTextClassifier, predict
from .train_baseline import train_baseline

__all__ = ["BaselineTextClassifier", "predict", "train_baseline"]
