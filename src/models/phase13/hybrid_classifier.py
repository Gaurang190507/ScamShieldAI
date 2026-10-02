"""Model D: Tactic-Aware and URL Hybrid Fusion Classifier for Phase 13.

Integrates:
1. Subword / Character n-gram text representations (Model B vectorizer).
2. Phase 6 Tactic indicators (23 canonical behavioral rules + evidence metrics).
3. Phase 4 Passive URL structural signals (14 offline heuristics + risk score).

Allows systematic comparison across:
- Text only
- Text + Tactic features
- Text + Tactic + URL features

OPERATIONAL INVARIANTS:
- 100% offline, zero network requests.
- Strict isolation of learned scaler and classifier.
"""

import json
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple, Union
import unicodedata

import joblib
import numpy as np
from scipy.sparse import csr_matrix, hstack
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.preprocessing import MaxAbsScaler

from src.preprocessing.extract_entities import extract_urls
from src.tactics.tactic_detector import TacticDetector
from src.tactics.tactic_rules import TACTIC_SEVERITY
from src.url_analysis.url_scanner import URLScanner
from .schemas import Phase13Prediction

# 23 Canonical Phase 6 tactics
CANONICAL_TACTICS: List[str] = [
    "remote_access_request",
    "otp_request",
    "credential_request",
    "payment_request",
    "secrecy_request",
    "account_suspension",
    "urgency",
    "threat",
    "impersonation",
    "fear_creation",
    "authority_claim",
    "verification_request",
    "link_redirection",
    "qr_code_request",
    "technical_support_claim",
    "personal_information_request",
    "investment_pressure",
    "emotional_manipulation",
    "romance_manipulation",
    "reward_claim",
    "job_offer",
    "delivery_problem",
    "refund_claim",
]

# 14 Canonical Phase 4 passive URL signals
URL_SIGNALS: List[str] = [
    "unusual_scheme",
    "userinfo_present",
    "ip_based_hostname",
    "plain_http_sensitive",
    "unusual_port",
    "excessive_subdomain_depth",
    "punycode_hostname",
    "suspicious_path_keywords",
    "suspicious_query_parameters",
    "known_shortener",
    "non_ascii_hostname",
    "excessive_url_length",
    "excessive_percent_encoding",
    "insecure_http",
]


class HybridFusionClassifier:
    """Tactic-aware and URL multimodal feature fusion classifier."""

    def __init__(
        self,
        model_dir: Optional[Union[str, Path]] = None,
        threshold: float = 0.35,
        include_tactics: bool = True,
        include_urls: bool = True,
        tactic_detector: Optional[TacticDetector] = None,
        url_scanner: Optional[URLScanner] = None,
    ):
        self.model_dir = Path(model_dir).resolve() if model_dir else None
        self.threshold = threshold
        self.include_tactics = include_tactics
        self.include_urls = include_urls

        self.tactic_detector = tactic_detector or TacticDetector()
        self.url_scanner = url_scanner or URLScanner()

        self.vectorizer: Optional[TfidfVectorizer] = None
        self.scaler: Optional[MaxAbsScaler] = None
        self.classifier: Optional[LogisticRegression] = None
        self.metadata: Dict[str, Any] = {}

        if self.model_dir and (self.model_dir / "hybrid_classifier.joblib").is_file():
            self.load(self.model_dir)

    def _extract_tactic_features(self, text: str) -> np.ndarray:
        """Extracts 25-dimensional tactic feature vector."""
        feats = np.zeros(len(CANONICAL_TACTICS) + 2, dtype=np.float32)
        if not self.include_tactics:
            return feats

        result = self.tactic_detector.detect(text)
        detected_names = set(result.tactic_names)

        for idx, tac in enumerate(CANONICAL_TACTICS):
            if tac in detected_names:
                feats[idx] = 1.0

        # Total evidence count
        total_evidence = sum(len(t.evidence) for t in result.tactics)
        feats[-2] = float(total_evidence)

        # Severity score
        sev_order = {"high": 3.0, "medium": 2.0, "low": 1.0}
        highest_sev = 0.0
        for t in result.tactics:
            highest_sev = max(highest_sev, sev_order.get(t.severity, 0.0))
        feats[-1] = highest_sev

        return feats

    def _extract_url_features(self, text: str) -> np.ndarray:
        """Extracts 15-dimensional URL heuristic feature vector."""
        feats = np.zeros(len(URL_SIGNALS) + 1, dtype=np.float32)
        if not self.include_urls:
            return feats

        urls = self.url_scanner.extract_urls(text)
        if not urls:
            return feats

        # Aggregate across all detected URLs
        triggered_signals = set()
        max_risk = 0.0
        for u in urls:
            res = self.url_scanner.analyze_url(u)
            for sig in res.get("signals", []):
                triggered_signals.add(sig.get("signal_name"))
            max_risk = max(max_risk, float(res.get("risk_score", 0.0)))

        for idx, sig in enumerate(URL_SIGNALS):
            if sig in triggered_signals:
                feats[idx] = 1.0

        feats[-1] = max_risk
        return feats

    def _extract_dense_auxiliary(self, texts: List[str]) -> np.ndarray:
        """Constructs stacked auxiliary feature matrix for a list of texts."""
        aux_list = []
        for t in texts:
            t_vec = self._extract_tactic_features(t)
            u_vec = self._extract_url_features(t)
            aux_list.append(np.concatenate([t_vec, u_vec]))
        return np.array(aux_list, dtype=np.float32)

    def fit(self, texts: List[str], labels: List[int]) -> "HybridFusionClassifier":
        """Fits text vectorizer, auxiliary scaler, and logistic regression model."""
        # 1. Text feature matrix
        norm_texts = [" ".join(unicodedata.normalize("NFKC", t).split()) for t in texts]
        self.vectorizer = TfidfVectorizer(
            analyzer="char_wb",
            ngram_range=(3, 5),
            min_df=1,
            max_features=12000,
            lowercase=True,
            sublinear_tf=True,
        )
        X_text = self.vectorizer.fit_transform(norm_texts)

        # 2. Auxiliary features
        aux_matrix = self._extract_dense_auxiliary(texts)
        self.scaler = MaxAbsScaler()
        aux_scaled = self.scaler.fit_transform(aux_matrix)
        X_aux = csr_matrix(aux_scaled)

        # 3. Stack features
        X_combined = hstack([X_text, X_aux], format="csr")

        # 4. Train classifier
        self.classifier = LogisticRegression(
            class_weight="balanced",
            C=1.0,
            solver="liblinear",
            random_state=42,
            max_iter=1000,
        )
        self.classifier.fit(X_combined, labels)

        self.metadata = {
            "model_type": "hybrid_fusion_logistic_regression",
            "include_tactics": self.include_tactics,
            "include_urls": self.include_urls,
            "num_text_features": X_text.shape[1],
            "num_aux_features": aux_matrix.shape[1],
            "threshold": self.threshold,
            "num_samples_trained": len(texts),
        }
        return self

    def predict_proba(self, text: str) -> Tuple[float, Dict[str, Any]]:
        """Computes scam probability and returns detected behavioral signals."""
        if self.vectorizer is None or self.scaler is None or self.classifier is None:
            raise RuntimeError("Model is not fitted or loaded.")

        norm_text = " ".join(unicodedata.normalize("NFKC", text).split())
        X_text = self.vectorizer.transform([norm_text])

        aux_raw = self._extract_dense_auxiliary([text])
        aux_scaled = self.scaler.transform(aux_raw)
        X_aux = csr_matrix(aux_scaled)

        X_combined = hstack([X_text, X_aux], format="csr")
        prob = float(self.classifier.predict_proba(X_combined)[0][1])

        # Gather signals for inspection
        tactic_res = self.tactic_detector.detect(text)
        urls = self.url_scanner.extract_urls(text)
        url_signals = []
        max_url_risk = 0.0
        max_url_level = "low"
        for u in urls:
            u_res = self.url_scanner.analyze_url(u)
            for sig in u_res.get("signals", []):
                sig_name = sig.get("signal_name")
                if sig_name and sig_name not in url_signals:
                    url_signals.append(sig_name)
            if float(u_res.get("risk_score", 0.0)) > max_url_risk:
                max_url_risk = float(u_res.get("risk_score", 0.0))
                max_url_level = u_res.get("risk_level", "low")

        sev_order = {"high": 3, "medium": 2, "low": 1}
        highest_sev = "none"
        for t in tactic_res.tactics:
            if sev_order.get(t.severity, 0) > sev_order.get(highest_sev, 0):
                highest_sev = t.severity

        signals = {
            "detected_tactics": tactic_res.tactic_names,
            "highest_severity": highest_sev,
            "evidence_count": sum(len(t.evidence) for t in tactic_res.tactics),
            "url_signals": url_signals,
            "url_risk_level": max_url_level,
            "url_risk_score": round(max_url_risk, 4),
        }
        return prob, signals

    def predict(self, text: str, sample_id: Optional[str] = None) -> Phase13Prediction:
        """Generates standard Phase 13 prediction object."""
        prob, signals = self.predict_proba(text)
        label = "scam" if prob >= self.threshold else "non_scam"

        features_used = ["char_wb_ngrams_3_5"]
        if self.include_tactics:
            features_used.append("phase6_tactic_indicators_25d")
        if self.include_urls:
            features_used.append("phase4_url_heuristics_15d")

        return Phase13Prediction(
            sample_id=sample_id,
            model_name="Model_D_HybridFusion",
            label=label,
            probability=prob,
            threshold=self.threshold,
            scam_probability=prob,
            non_scam_probability=1.0 - prob,
            features_used=features_used,
            signals_detected=signals,
        )

    def save(self, output_dir: Union[str, Path]) -> None:
        """Serializes hybrid artifacts to disk."""
        out = Path(output_dir).resolve()
        out.mkdir(parents=True, exist_ok=True)
        joblib.dump(self.vectorizer, out / "hybrid_vectorizer.joblib")
        joblib.dump(self.scaler, out / "hybrid_scaler.joblib")
        joblib.dump(self.classifier, out / "hybrid_classifier.joblib")
        self.metadata["threshold"] = self.threshold
        with open(out / "metadata.json", "w", encoding="utf-8") as f:
            json.dump(self.metadata, f, indent=2)

    def load(self, model_dir: Union[str, Path]) -> None:
        """Loads serialized hybrid artifacts from disk."""
        in_dir = Path(model_dir).resolve()
        self.vectorizer = joblib.load(in_dir / "hybrid_vectorizer.joblib")
        self.scaler = joblib.load(in_dir / "hybrid_scaler.joblib")
        self.classifier = joblib.load(in_dir / "hybrid_classifier.joblib")
        meta_file = in_dir / "metadata.json"
        if meta_file.is_file():
            with open(meta_file, "r", encoding="utf-8") as f:
                self.metadata = json.load(f)
                self.threshold = float(self.metadata.get("threshold", self.threshold))
        self.model_dir = in_dir
