"""Model C: Offline Dense Semantic Representation Classifier for Phase 13.

Utilizes local sentence-transformers (all-MiniLM-L6-v2) embedding representation
coupled with Logistic Regression.

OPERATIONAL INVARIANTS:
- 100% offline, zero network calls, zero socket downloads.
- Relies exclusively on locally cached HuggingFace model weights.
- Serialized artifacts stored in models/phase13/semantic_dense/.
"""

import json
from pathlib import Path
from typing import Any, Dict, List, Optional, Union

import joblib
import numpy as np
from sklearn.linear_model import LogisticRegression

from src.semantic.embedder import TextEmbedder
from .schemas import Phase13Prediction


class SemanticDenseClassifier:
    """Offline semantic sentence embedding + Logistic Regression classifier."""

    def __init__(
        self,
        model_dir: Optional[Union[str, Path]] = None,
        embedder: Optional[TextEmbedder] = None,
        threshold: float = 0.40,
    ):
        self.model_dir = Path(model_dir).resolve() if model_dir else None
        self.embedder = embedder or TextEmbedder()
        self.threshold = threshold
        self.classifier: Optional[LogisticRegression] = None
        self.metadata: Dict[str, Any] = {}

        if self.model_dir and (self.model_dir / "semantic_classifier.joblib").is_file():
            self.load(self.model_dir)

    def fit(self, texts: List[str], labels: List[int]) -> "SemanticDenseClassifier":
        """Fits the logistic regression classifier on offline dense embeddings."""
        embeddings = self.embedder.embed_batch(texts)

        self.classifier = LogisticRegression(
            class_weight="balanced",
            C=1.0,
            solver="liblinear",
            random_state=42,
            max_iter=1000,
        )
        self.classifier.fit(embeddings, labels)

        self.metadata = {
            "model_type": "offline_semantic_dense_logistic_regression",
            "embedder_model": self.embedder.model_name,
            "embedding_dimension": int(embeddings.shape[1]),
            "threshold": self.threshold,
            "num_samples_trained": len(texts),
            "offline_verified": True,
        }
        return self

    def predict_proba(self, text: str) -> float:
        """Computes scam probability using dense embedding."""
        if self.classifier is None:
            raise RuntimeError("Model is not fitted or loaded.")

        if not text.strip():
            return 0.0

        vec = self.embedder.embed_text(text).reshape(1, -1)
        prob = float(self.classifier.predict_proba(vec)[0][1])
        return prob

    def predict(self, text: str, sample_id: Optional[str] = None) -> Phase13Prediction:
        """Predicts class label and structured metrics for the given message."""
        prob = self.predict_proba(text)
        label = "scam" if prob >= self.threshold else "non_scam"

        return Phase13Prediction(
            sample_id=sample_id,
            model_name="Model_C_SemanticDense",
            label=label,
            probability=prob,
            threshold=self.threshold,
            scam_probability=prob,
            non_scam_probability=1.0 - prob,
            features_used=["dense_minilm_l6_embeddings_384d"],
            signals_detected={},
        )

    def save(self, output_dir: Union[str, Path]) -> None:
        """Serializes model artifacts to disk."""
        out = Path(output_dir).resolve()
        out.mkdir(parents=True, exist_ok=True)
        joblib.dump(self.classifier, out / "semantic_classifier.joblib")
        self.metadata["threshold"] = self.threshold
        with open(out / "metadata.json", "w", encoding="utf-8") as f:
            json.dump(self.metadata, f, indent=2)

    def load(self, model_dir: Union[str, Path]) -> None:
        """Loads serialized model artifacts from disk."""
        in_dir = Path(model_dir).resolve()
        self.classifier = joblib.load(in_dir / "semantic_classifier.joblib")
        meta_file = in_dir / "metadata.json"
        if meta_file.is_file():
            with open(meta_file, "r", encoding="utf-8") as f:
                self.metadata = json.load(f)
                self.threshold = float(self.metadata.get("threshold", self.threshold))
        self.model_dir = in_dir
