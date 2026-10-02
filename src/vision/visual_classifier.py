"""Supervised visual scam classifier for ScamShield AI Phase 9B.

OPERATIONAL INVARIANTS:
1. Feature Normalization: Uses StandardScaler fitted strictly on the TRAINING split.
2. Supervised Learning: Uses Logistic Regression fitted strictly on the TRAINING split.
3. Threshold Calibration: Threshold tuned exclusively on the VALIDATION split.
4. Total Split Isolation: Test split is NEVER observed during training or threshold tuning.
5. Explainability: Exposes model coefficients directly mapped to feature names.
"""

import json
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Tuple, Union
import numpy as np
from PIL import Image
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import f1_score, precision_score, recall_score
from sklearn.preprocessing import StandardScaler

from .image_features import extract_visual_features
from .schemas import VisualFeatures, VisualSampleRecord


class VisualScamClassifier:
    """Supervised statistical classifier operating on pixel and layout features."""

    def __init__(
        self,
        C: float = 1.0,
        random_state: int = 42,
        default_threshold: float = 0.50,
    ):
        """Initializes classifier hyperparameters."""
        self.C = C
        self.random_state = random_state
        self.threshold = default_threshold

        self.scaler = StandardScaler()
        self.model = LogisticRegression(
            C=self.C,
            solver="lbfgs",
            random_state=self.random_state,
            max_iter=1000,
        )
        self.is_fitted = False
        self.threshold_tuned = False
        self.feature_names = VisualFeatures.feature_names()

    def _extract_feature_vector(
        self,
        item: Union[VisualSampleRecord, VisualFeatures, Image.Image, Path, str, Sequence[float]],
    ) -> List[float]:
        """Converts diverse input types into canonical ordered feature vector."""
        if isinstance(item, VisualFeatures):
            return item.to_feature_vector()
        elif isinstance(item, VisualSampleRecord):
            # Load image from disk and extract
            img_path = Path(item.image_path)
            if not img_path.is_file():
                # Try relative to cwd or data/visual
                alt_path = Path("data/visual/synthetic") / Path(item.image_path).name
                if alt_path.is_file():
                    img_path = alt_path
            with Image.open(img_path) as img:
                feat = extract_visual_features(img)
            return feat.to_feature_vector()
        elif isinstance(item, Image.Image):
            feat = extract_visual_features(item)
            return feat.to_feature_vector()
        elif isinstance(item, (str, Path)):
            with Image.open(item) as img:
                feat = extract_visual_features(img)
            return feat.to_feature_vector()
        elif isinstance(item, (list, tuple, np.ndarray)):
            return [float(x) for x in item]
        else:
            raise TypeError(f"Unsupported feature input type: {type(item)}")

    def fit(
        self,
        train_records: Sequence[Union[VisualSampleRecord, Tuple[VisualFeatures, str]]],
    ) -> "VisualScamClassifier":
        """Fits scaler and logistic regression model strictly on training samples.

        Args:
            train_records: Collection of VisualSampleRecord instances or (VisualFeatures, label) tuples.

        Returns:
            Self.
        """
        if not train_records:
            raise ValueError("Cannot fit classifier on empty training records.")

        X_list: List[List[float]] = []
        y_list: List[int] = []

        for item in train_records:
            if isinstance(item, VisualSampleRecord):
                if item.split is not None and item.split != "train":
                    raise ValueError(
                        f"CRITICAL LEAKAGE ATTEMPT: Record {item.image_id} has split='{item.split}', "
                        "expected 'train'. Classifier must only fit on train split."
                    )
                vec = self._extract_feature_vector(item)
                label_num = 1 if item.label == "scam" else 0
            elif isinstance(item, tuple) and len(item) == 2:
                feat, lbl = item
                vec = self._extract_feature_vector(feat)
                label_num = 1 if lbl == "scam" else 0
            else:
                raise TypeError(f"Unsupported record format: {type(item)}")

            X_list.append(vec)
            y_list.append(label_num)

        X = np.array(X_list, dtype=np.float32)
        y = np.array(y_list, dtype=np.int32)

        # Ensure both classes are present
        if len(np.unique(y)) < 2:
            raise ValueError("Training set must contain at least one scam and one non-scam sample.")

        X_scaled = self.scaler.fit_transform(X)
        self.model.fit(X_scaled, y)
        self.is_fitted = True
        return self

    def tune_threshold(
        self,
        val_records: Sequence[Union[VisualSampleRecord, Tuple[VisualFeatures, str]]],
        candidate_thresholds: Optional[Sequence[float]] = None,
    ) -> float:
        """Optimizes decision threshold strictly on the validation set.

        Searches candidate thresholds to maximize balanced F1 score.

        Args:
            val_records: Collection of validation records.
            candidate_thresholds: Candidate decision boundaries.

        Returns:
            The selected optimal threshold.
        """
        if not self.is_fitted:
            raise RuntimeError("Classifier must be fitted on train split before tuning threshold.")
        if not val_records:
            return self.threshold

        if candidate_thresholds is None:
            candidate_thresholds = np.linspace(0.15, 0.85, 15)

        val_probs: List[float] = []
        val_targets: List[int] = []

        for item in val_records:
            if isinstance(item, VisualSampleRecord):
                if item.split is not None and item.split != "val":
                    raise ValueError(
                        f"CRITICAL LEAKAGE ATTEMPT: Record {item.image_id} has split='{item.split}', "
                        "expected 'val'. Threshold tuning must only use validation split."
                    )
                prob = self.predict_proba(item)
                lbl = 1 if item.label == "scam" else 0
            elif isinstance(item, tuple) and len(item) == 2:
                feat, lbl_str = item
                prob = self.predict_proba(feat)
                lbl = 1 if lbl_str == "scam" else 0
            else:
                raise TypeError(f"Unsupported record format: {type(item)}")

            val_probs.append(prob)
            val_targets.append(lbl)

        y_true = np.array(val_targets)
        probs = np.array(val_probs)

        best_score = -1.0
        best_thresh = self.threshold

        for thresh in candidate_thresholds:
            y_pred = (probs >= thresh).astype(int)
            # Evaluate F1 score on positive class
            score = f1_score(y_true, y_pred, zero_division=0)
            if score > best_score:
                best_score = score
                best_thresh = float(thresh)

        self.threshold = round(best_thresh, 4)
        self.threshold_tuned = True
        return self.threshold

    def predict_proba(
        self,
        item: Union[VisualSampleRecord, VisualFeatures, Image.Image, Path, str, Sequence[float]],
    ) -> float:
        """Estimates probability that sample is a scam.

        Returns:
            Float probability in [0.0, 1.0].
        """
        if not self.is_fitted:
            raise RuntimeError("Classifier is not fitted. Call fit() first.")

        vec = self._extract_feature_vector(item)
        X = np.array([vec], dtype=np.float32)
        X_scaled = self.scaler.transform(X)
        probs = self.model.predict_proba(X_scaled)[0]
        # Class index 1 corresponds to scam
        scam_prob = float(probs[1])
        return round(scam_prob, 4)

    def predict(
        self,
        item: Union[VisualSampleRecord, VisualFeatures, Image.Image, Path, str, Sequence[float]],
        threshold: Optional[float] = None,
    ) -> Tuple[str, float]:
        """Predicts class label and probability.

        Args:
            item: Visual feature input.
            threshold: Optional custom threshold; defaults to self.threshold.

        Returns:
            Tuple of (label: "scam" | "non_scam", scam_probability: float).
        """
        prob = self.predict_proba(item)
        thresh = threshold if threshold is not None else self.threshold
        label = "scam" if prob >= thresh else "non_scam"
        return label, prob

    def get_feature_importances(self) -> Dict[str, float]:
        """Returns logistic regression weights associated with each visual feature."""
        if not self.is_fitted:
            raise RuntimeError("Classifier is not fitted.")

        coefs = self.model.coef_[0]
        return {name: round(float(coef), 4) for name, coef in zip(self.feature_names, coefs)}

    def to_dict(self) -> Dict[str, Any]:
        """Serializes fitted classifier state for transparency and audit."""
        return {
            "is_fitted": self.is_fitted,
            "threshold_tuned": self.threshold_tuned,
            "threshold": self.threshold,
            "C": self.C,
            "random_state": self.random_state,
            "feature_names": self.feature_names,
            "coefficients": self.get_feature_importances() if self.is_fitted else {},
            "intercept": round(float(self.model.intercept_[0]), 4) if self.is_fitted else 0.0,
            "scaler_mean": [round(float(m), 4) for m in self.scaler.mean_] if self.is_fitted else [],
            "scaler_scale": [round(float(s), 4) for s in self.scaler.scale_] if self.is_fitted else [],
        }

    def save(self, filepath: Union[str, Path]) -> None:
        """Saves model metadata and parameters to JSON file."""
        Path(filepath).write_text(json.dumps(self.to_dict(), indent=2), encoding="utf-8")
