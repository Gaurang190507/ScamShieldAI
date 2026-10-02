"""End-to-end Case Assessment Pipeline for ScamShield AI Phase 8.

Coordinates multi-signal evaluation across all offline frozen components:
- Phase 3: Text Classifier (TF-IDF + Logistic Regression)
- Phase 4: Passive URL Analysis (structural heuristics)
- Phase 6: Scam Tactic Detection (behavioral rules + grounded spans)
- Phase 7: Semantic Similarity & Novelty (NumPy reference search)
- Phase 8: Risk Aggregator (deterministic, rule-based forensic evaluation)

Zero network access. Fully offline and reproducible.
"""

from pathlib import Path
from typing import Any, Dict, List, Optional, Union
import numpy as np

from .aggregator import RiskAggregator
from .schemas import CaseAssessmentInput, CaseAssessmentResult
from src.models.baseline_classifier import BaselineTextClassifier
from src.url_analysis.url_scanner import URLScanner
from src.tactics.tactic_detector import TacticDetector
from src.semantic.analyzer import SemanticAnalyzer
from src.semantic.reference_index import SemanticReferenceIndex


class CaseAssessmentPipeline:
    """Unified offline pipeline orchestrating multi-signal case assessments."""

    def __init__(
        self,
        classifier: Optional[BaselineTextClassifier] = None,
        url_scanner: Optional[URLScanner] = None,
        tactic_detector: Optional[TacticDetector] = None,
        semantic_analyzer: Optional[SemanticAnalyzer] = None,
        aggregator: Optional[RiskAggregator] = None,
        models_dir: Optional[Union[str, Path]] = None,
        semantic_ref_dir: Optional[Union[str, Path]] = None,
        enable_semantic: bool = True,
        classifier_threshold: Optional[float] = 0.30,
    ):
        """Initializes the multi-signal assessment pipeline.

        Args:
            classifier: Pre-instantiated BaselineTextClassifier. If None, loaded from disk.
            url_scanner: Pre-instantiated URLScanner. If None, created.
            tactic_detector: Pre-instantiated TacticDetector. If None, created.
            semantic_analyzer: Pre-instantiated SemanticAnalyzer. If None, loaded if enabled.
            aggregator: Pre-instantiated RiskAggregator. If None, created.
            models_dir: Path to baseline model directory (default: models/baseline).
            semantic_ref_dir: Path to semantic reference directory (default: data/semantic/reference).
            enable_semantic: Whether to run semantic embeddings and similarity.
            classifier_threshold: Operating decision threshold for Phase 3 classifier.
        """
        project_root = Path(__file__).resolve().parents[2]

        # 1. Phase 3 Text Classifier
        if classifier is not None:
            self.classifier = classifier
        else:
            clf_dir = Path(models_dir) if models_dir else (project_root / "models" / "baseline")
            if (clf_dir / "tfidf_vectorizer.joblib").is_file():
                self.classifier = BaselineTextClassifier(
                    model_dir=clf_dir, threshold=classifier_threshold
                )
            else:
                self.classifier = None

        # 2. Phase 4 URL Scanner
        self.url_scanner = url_scanner or URLScanner()

        # 3. Phase 6 Tactic Detector
        self.tactic_detector = tactic_detector or TacticDetector()

        # 4. Phase 7 Semantic Analyzer (optional / lazy)
        self.enable_semantic = enable_semantic
        if semantic_analyzer is not None:
            self.semantic_analyzer = semantic_analyzer
        elif enable_semantic:
            ref_dir = (
                Path(semantic_ref_dir)
                if semantic_ref_dir
                else (project_root / "data" / "semantic" / "reference")
            )
            if (ref_dir / "reference_items.jsonl").is_file():
                try:
                    ref_index = SemanticReferenceIndex.load(ref_dir)
                    self.semantic_analyzer = SemanticAnalyzer(reference_index=ref_index)
                except Exception:
                    self.semantic_analyzer = None
            else:
                self.semantic_analyzer = None
        else:
            self.semantic_analyzer = None

        # 5. Phase 8 Aggregator
        self.aggregator = aggregator or RiskAggregator()

    def analyze(
        self,
        text: str,
        sample_id: Optional[str] = None,
        urls: Optional[List[str]] = None,
        disallow_same_id: bool = False,
    ) -> CaseAssessmentResult:
        """Runs end-to-end multi-signal analysis for a single message.

        Args:
            text: Raw message content.
            sample_id: Optional unique identifier.
            urls: Optional pre-extracted URLs. If None, extracted automatically.
            disallow_same_id: Whether semantic search disallows the same sample ID.

        Returns:
            Structured CaseAssessmentResult.
        """
        clean_text = text if isinstance(text, str) else ""

        # --- Phase 4: URL Analysis ---
        extracted_urls = urls if urls is not None else self.url_scanner.extract_urls(clean_text)
        url_count = len(extracted_urls)
        url_risk_scores: List[float] = []
        url_signals: List[Dict[str, Any]] = []

        for u in extracted_urls:
            try:
                u_res = self.url_scanner.analyze_url(u)
                score = u_res.get("risk_score", 0.0)
                url_risk_scores.append(score)
                for sig in u_res.get("signals", []):
                    sig_copy = dict(sig)
                    sig_copy["url"] = u
                    url_signals.append(sig_copy)
            except Exception:
                pass

        url_risk_max = max(url_risk_scores) if url_risk_scores else 0.0
        url_risk_mean = float(np.mean(url_risk_scores)) if url_risk_scores else 0.0

        # --- Phase 6: Tactic Detection ---
        try:
            tactic_res = self.tactic_detector.detect(
                text=clean_text, sample_id=sample_id, urls=extracted_urls
            )
            detected_tactics: List[str] = [t.tactic for t in tactic_res.tactics]
            tactic_evidence: List[Dict[str, Any]] = []
            for t in tactic_res.tactics:
                for span in t.evidence:
                    tactic_evidence.append(
                        {
                            "tactic": t.tactic,
                            "matched_text": span.matched_text,
                            "start": span.start,
                            "end": span.end,
                            "severity": span.severity or t.severity,
                            "reason": span.reason,
                        }
                    )
        except Exception:
            detected_tactics = []
            tactic_evidence = []

        # --- Phase 3 / Phase 13: Text Classifier ---
        if self.classifier is not None:
            try:
                raw_res = self.classifier.predict(clean_text)
                clf_res = raw_res.to_dict() if hasattr(raw_res, "to_dict") else raw_res
                p = float(clf_res.get("probability", 0.0))
                thresh = float(clf_res.get("threshold", 0.30))
                label = str(clf_res.get("label", "non_scam"))
            except Exception:
                p = None
                thresh = 0.30
                label = None
        else:
            p = None
            thresh = 0.30
            label = None

        # --- Phase 7: Semantic Similarity & Novelty ---
        top1_sim = None
        top_k_sims: List[float] = []
        novelty_score = None
        semantic_status = None

        if self.enable_semantic and self.semantic_analyzer is not None and clean_text.strip():
            try:
                sem_res = self.semantic_analyzer.analyze(
                    text=clean_text,
                    sample_id=sample_id,
                    top_k=5,
                    disallow_same_id=disallow_same_id,
                )
                top1_sim = sem_res.semantic.top_1_similarity
                top_k_sims = [n.similarity for n in sem_res.neighbors]
                novelty_score = sem_res.semantic.semantic_novelty_score
                semantic_status = sem_res.semantic.semantic_status
            except Exception:
                top1_sim = None
                top_k_sims = []
                novelty_score = None
                semantic_status = None

        # Assemble CaseAssessmentInput
        case_input = CaseAssessmentInput(
            sample_id=sample_id,
            text=clean_text,
            text_classifier_probability=p,
            text_classifier_threshold=thresh,
            text_classifier_label=label,
            url_count=url_count,
            url_risk_score_max=round(url_risk_max, 4),
            url_risk_score_mean=round(url_risk_mean, 4),
            url_signals=url_signals,
            detected_tactics=detected_tactics,
            tactic_evidence=tactic_evidence,
            top1_similarity=round(top1_sim, 4) if top1_sim is not None else None,
            top_k_similarities=[round(s, 4) for s in top_k_sims],
            semantic_novelty_score=round(novelty_score, 4) if novelty_score is not None else None,
            semantic_status=semantic_status,
            known_pattern_status=semantic_status,
        )

        return self.aggregator.aggregate(case_input)

    def analyze_input(self, case_input: CaseAssessmentInput) -> CaseAssessmentResult:
        """Directly aggregates an existing CaseAssessmentInput.

        Args:
            case_input: Pre-constructed CaseAssessmentInput.

        Returns:
            Structured CaseAssessmentResult.
        """
        return self.aggregator.aggregate(case_input)

    def analyze_batch(
        self,
        records: List[Dict[str, Any]],
        text_field: str = "text",
        id_field: str = "sample_id",
        urls_field: str = "urls",
    ) -> List[CaseAssessmentResult]:
        """Runs assessment pipeline on a list of record dictionaries.

        Args:
            records: List of sample dictionaries.
            text_field: Dictionary key for message text.
            id_field: Dictionary key for sample ID.
            urls_field: Dictionary key for pre-extracted URLs.

        Returns:
            List of CaseAssessmentResult objects.
        """
        results: List[CaseAssessmentResult] = []
        for r in records:
            txt = r.get(text_field, "")
            sid = r.get(id_field)
            urls = r.get(urls_field)
            results.append(self.analyze(text=txt, sample_id=sid, urls=urls))
        return results
