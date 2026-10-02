"""Reusable prediction interface for ScamShield AI Phase 3 baseline text classifier."""

import json
from pathlib import Path
from typing import Dict, Any, Optional, Union
import joblib


class BaselineTextClassifier:
    """Inference interface for TF-IDF + Logistic Regression text baseline."""

    def __init__(
        self,
        model_dir: Optional[Union[str, Path]] = None,
        threshold: Optional[float] = None,
    ):
        """Initializes and loads the baseline model from artifacts.

        Args:
            model_dir: Directory containing serialized model artifacts.
            threshold: Decision threshold for the scam class. If None, reads from metadata or defaults to 0.5.
        """
        if model_dir is None:
            model_dir = Path(__file__).resolve().parents[2] / "models" / "baseline"
        self.model_dir = Path(model_dir).resolve()

        self.vectorizer = None
        self.classifier = None
        self.metadata = {}
        self.threshold = threshold

        if (self.model_dir / "tfidf_vectorizer.joblib").is_file():
            self.load(self.model_dir)

    def load(self, model_dir: Union[str, Path]) -> None:
        """Loads serialized model artifacts from disk.

        Args:
            model_dir: Directory containing joblib files and metadata JSON.
        """
        dir_path = Path(model_dir).resolve()
        vec_path = dir_path / "tfidf_vectorizer.joblib"
        clf_path = dir_path / "logistic_regression.joblib"
        meta_path = dir_path / "model_metadata.json"

        if not vec_path.is_file():
            raise FileNotFoundError(f"TF-IDF vectorizer artifact not found: {vec_path}")
        if not clf_path.is_file():
            raise FileNotFoundError(f"Classifier artifact not found: {clf_path}")

        self.vectorizer = joblib.load(vec_path)
        self.classifier = joblib.load(clf_path)

        if meta_path.is_file():
            with open(meta_path, "r", encoding="utf-8") as f:
                self.metadata = json.load(f)

        if self.threshold is None:
            self.threshold = float(self.metadata.get("selected_threshold", 0.50))

        self.model_dir = dir_path

    def predict(self, text: str) -> Dict[str, Any]:
        """Predicts whether an inbound text message is a scam or non-scam.

        Args:
            text: Raw or normalized message string.

        Returns:
            Structured prediction dictionary containing:
            - label: 'scam' or 'non_scam'
            - probability: float in [0.0, 1.0] (scam probability)
            - threshold: float in [0.0, 1.0] (operating decision threshold)
            - scam_probability: float in [0.0, 1.0]
            - non_scam_probability: float in [0.0, 1.0]
        """
        if self.vectorizer is None or self.classifier is None:
            raise RuntimeError(
                f"Model artifacts not loaded. Ensure '{self.model_dir}' contains valid artifacts."
            )

        if not isinstance(text, str) or not text.strip():
            return {
                "label": "non_scam",
                "probability": 0.0,
                "threshold": float(self.threshold),
                "scam_probability": 0.0,
                "non_scam_probability": 1.0,
            }

        # Transform raw text via fitted TF-IDF
        X_vec = self.vectorizer.transform([text])

        # Predict class probabilities
        probs = self.classifier.predict_proba(X_vec)[0]
        # In binary classification, classes are [0, 1] mapped to [non_scam, scam]
        scam_prob = float(probs[1])
        non_scam_prob = float(probs[0])

        label = "scam" if scam_prob >= self.threshold else "non_scam"

        return {
            "label": label,
            "probability": round(scam_prob, 4),
            "threshold": round(float(self.threshold), 4),
            "scam_probability": round(scam_prob, 4),
            "non_scam_probability": round(non_scam_prob, 4),
        }


# Global cached classifier instance for fast repeated calls
_CACHED_CLASSIFIER: Optional[BaselineTextClassifier] = None


def predict(
    text: str,
    model_dir: Optional[Union[str, Path]] = None,
    threshold: Optional[float] = None,
) -> Dict[str, Any]:
    """Convenience function to classify message text using the baseline model.

    Args:
        text: Raw inbound message text.
        model_dir: Optional custom model directory.
        threshold: Optional custom decision threshold.

    Returns:
        Structured prediction dictionary.
    """
    global _CACHED_CLASSIFIER
    if _CACHED_CLASSIFIER is None or model_dir is not None or threshold is not None:
        clf = BaselineTextClassifier(model_dir=model_dir, threshold=threshold)
        if model_dir is None and threshold is None:
            _CACHED_CLASSIFIER = clf
        return clf.predict(text)
    return _CACHED_CLASSIFIER.predict(text)
