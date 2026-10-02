"""Model B: Subword / Character n-gram TF-IDF Text Classifier for Phase 13.

Designed to address:
- Native Devanagari Hindi (robust to character sequences and unicode variants)
- Romanized Hinglish (robust to phonetic transliterations)
- Obfuscations (leetspeak, character spacing, punctuation injection)

OPERATIONAL INVARIANTS:
- 100% offline, zero network activity.
- Deterministic Unicode NFKC normalization.
- Serialized artifacts isolated in models/phase13/char_ngram/.
"""

import json
from pathlib import Path
from typing import Any, Dict, List, Optional, Union
import unicodedata

import joblib
import numpy as np
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression

from .schemas import Phase13Prediction


def normalize_unicode(text: str) -> str:
    """Performs Unicode NFKC normalization and whitespace standardization."""
    if not isinstance(text, str):
        return ""
    normalized = unicodedata.normalize("NFKC", text)
    return " ".join(normalized.split())


class CharNgramClassifier:
    """Character/subword n-gram TF-IDF + Logistic Regression classifier."""

    def __init__(
        self,
        model_dir: Optional[Union[str, Path]] = None,
        threshold: float = 0.35,
        ngram_range: tuple = (3, 5),
        max_features: int = 15000,
    ):
        self.model_dir = Path(model_dir).resolve() if model_dir else None
        self.threshold = threshold
        self.ngram_range = ngram_range
        self.max_features = max_features
        self.vectorizer: Optional[TfidfVectorizer] = None
        self.classifier: Optional[LogisticRegression] = None
        self.metadata: Dict[str, Any] = {}

        if self.model_dir and (self.model_dir / "char_vectorizer.joblib").is_file():
            self.load(self.model_dir)

    def fit(self, texts: List[str], labels: List[int]) -> "CharNgramClassifier":
        """Fits the character n-gram TF-IDF vectorizer and logistic regression model.

        Args:
            texts: List of raw input texts.
            labels: List of binary integer labels (1 for scam, 0 for non_scam).
        """
        cleaned_texts = [normalize_unicode(t) for t in texts]

        self.vectorizer = TfidfVectorizer(
            analyzer="char_wb",
            ngram_range=self.ngram_range,
            min_df=1,
            max_features=self.max_features,
            lowercase=True,
            sublinear_tf=True,
        )
        X = self.vectorizer.fit_transform(cleaned_texts)

        self.classifier = LogisticRegression(
            class_weight="balanced",
            C=1.0,
            solver="liblinear",
            random_state=42,
            max_iter=1000,
        )
        self.classifier.fit(X, labels)

        self.metadata = {
            "model_type": "char_ngram_tfidf_logistic_regression",
            "ngram_range": list(self.ngram_range),
            "max_features": self.max_features,
            "vocabulary_size": len(self.vectorizer.vocabulary_),
            "threshold": self.threshold,
            "num_samples_trained": len(texts),
        }
        return self

    def predict_proba(self, text: str) -> float:
        """Returns the predicted scam probability for the input text."""
        if self.vectorizer is None or self.classifier is None:
            raise RuntimeError("Model is not fitted or loaded.")

        cleaned = normalize_unicode(text)
        if not cleaned:
            return 0.0

        vec = self.vectorizer.transform([cleaned])
        prob = float(self.classifier.predict_proba(vec)[0][1])
        return prob

    def predict(self, text: str, sample_id: Optional[str] = None) -> Phase13Prediction:
        """Predicts class label and structured metrics for the given message."""
        prob = self.predict_proba(text)
        label = "scam" if prob >= self.threshold else "non_scam"

        return Phase13Prediction(
            sample_id=sample_id,
            model_name="Model_B_CharNgram",
            label=label,
            probability=prob,
            threshold=self.threshold,
            scam_probability=prob,
            non_scam_probability=1.0 - prob,
            features_used=["char_wb_ngrams_3_5"],
            signals_detected={},
        )

    def save(self, output_dir: Union[str, Path]) -> None:
        """Serializes model artifacts to the specified directory."""
        out = Path(output_dir).resolve()
        out.mkdir(parents=True, exist_ok=True)
        joblib.dump(self.vectorizer, out / "char_vectorizer.joblib")
        joblib.dump(self.classifier, out / "char_classifier.joblib")
        self.metadata["threshold"] = self.threshold
        with open(out / "metadata.json", "w", encoding="utf-8") as f:
            json.dump(self.metadata, f, indent=2)

    def load(self, model_dir: Union[str, Path]) -> None:
        """Loads serialized model artifacts from disk."""
        in_dir = Path(model_dir).resolve()
        self.vectorizer = joblib.load(in_dir / "char_vectorizer.joblib")
        self.classifier = joblib.load(in_dir / "char_classifier.joblib")
        meta_file = in_dir / "metadata.json"
        if meta_file.is_file():
            with open(meta_file, "r", encoding="utf-8") as f:
                self.metadata = json.load(f)
                self.threshold = float(self.metadata.get("threshold", self.threshold))
        self.model_dir = in_dir
