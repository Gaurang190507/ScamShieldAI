"""Validation engine ensuring strict compliance with ScamShield AI schema and vocabulary."""

from dataclasses import dataclass, field
from datetime import datetime
from typing import List, Dict, Any, Iterable, Union, Set
from urllib.parse import urlparse
import numpy as np
import pandas as pd

from .dataset_schema import (
    REQUIRED_COLUMNS,
    Label,
    SourceType,
    ScamCategory,
    RequestedAction,
    TargetAsset,
    UrgencyLevel,
    ImpersonatedEntity,
    LabelConfidence,
    KnownUnknownStatus,
    get_controlled_tactics,
)


@dataclass
class ValidationResult:
    """Holds validation status, error messages, and sample metrics."""
    is_valid: bool
    errors: List[str] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)
    sample_count: int = 0

    def summary(self) -> str:
        """Returns a formatted human-readable summary."""
        status = "PASSED" if self.is_valid else "FAILED"
        err_count = len(self.errors)
        lines = [f"Dataset Validation {status}: {self.sample_count} sample(s) checked, {err_count} error(s)."]
        if self.errors:
            lines.append("Errors encountered:")
            for e in self.errors[:15]:  # Show first 15 errors
                lines.append(f"  - {e}")
            if len(self.errors) > 15:
                lines.append(f"  ... and {len(self.errors) - 15} additional error(s).")
        return "\n".join(lines)


class DatasetValidator:
    """Validates records and datasets against ScamShield AI specifications without silent mutation."""

    def __init__(self, allowed_tactics: Set[str] = None):
        self.allowed_tactics = allowed_tactics or get_controlled_tactics()
        self._allowed_labels = {e.value for e in Label}
        self._allowed_source_types = {e.value for e in SourceType}
        self._allowed_categories = {e.value for e in ScamCategory}
        self._allowed_actions = {e.value for e in RequestedAction}
        self._allowed_assets = {e.value for e in TargetAsset}
        self._allowed_urgency = {e.value for e in UrgencyLevel}
        self._allowed_entities = {e.value for e in ImpersonatedEntity}
        self._allowed_confidence = {e.value for e in LabelConfidence}
        self._allowed_status = {e.value for e in KnownUnknownStatus}

    def validate_record(self, record: Dict[str, Any], record_idx: int = 0) -> List[str]:
        """Validates a single sample dictionary.

        Args:
            record: Dictionary containing sample attributes.
            record_idx: Index of record for contextual error messaging.

        Returns:
            List of error strings (empty if valid).
        """
        errors: List[str] = []
        sample_id = str(record.get("sample_id", f"idx_{record_idx}"))
        prefix = f"Sample [{sample_id}] (row {record_idx}): "

        # 1. Required column presence
        missing_cols = [c for c in REQUIRED_COLUMNS if c not in record]
        if missing_cols:
            errors.append(f"{prefix}Missing required column(s): {', '.join(missing_cols)}")
            return errors  # Abort deep validation if core columns are absent

        # 2. sample_id non-empty string
        s_id = record.get("sample_id")
        if not isinstance(s_id, str) or not s_id.strip():
            errors.append(f"{prefix}'sample_id' must be a non-empty string.")

        # 3. text non-empty string
        text = record.get("text")
        if not isinstance(text, str) or not text.strip():
            errors.append(f"{prefix}'text' must be a non-empty string.")
        text_str = str(text) if text is not None else ""

        # 4. language non-empty string
        language = record.get("language")
        if not isinstance(language, str) or not language.strip():
            errors.append(f"{prefix}'language' must be a non-empty string code (e.g., 'en').")

        # 5. source_type in allowed enum
        st = record.get("source_type")
        if st not in self._allowed_source_types:
            errors.append(
                f"{prefix}Invalid source_type '{st}'. Allowed: {sorted(self._allowed_source_types)}"
            )

        # 6. label in allowed enum
        lbl = record.get("label")
        if lbl not in self._allowed_labels:
            errors.append(f"{prefix}Invalid label '{lbl}'. Allowed: {sorted(self._allowed_labels)}")

        # 7. scam_category in allowed enum
        cat = record.get("scam_category")
        if cat not in self._allowed_categories:
            errors.append(
                f"{prefix}Invalid scam_category '{cat}'. Allowed: {sorted(self._allowed_categories)}"
            )

        # 8. tactics controlled vocabulary validation
        tactics = record.get("tactics")
        if not isinstance(tactics, list):
            errors.append(f"{prefix}'tactics' must be a list of strings.")
        else:
            invalid_tactics = [t for t in tactics if not isinstance(t, str) or t not in self.allowed_tactics]
            if invalid_tactics:
                errors.append(
                    f"{prefix}Unknown tactic(s) {invalid_tactics} not in controlled vocabulary."
                )

        # 9. evidence_spans structure and verbatim check
        evidence = record.get("evidence_spans")
        if not isinstance(evidence, list):
            errors.append(f"{prefix}'evidence_spans' must be a list of dictionary objects.")
        else:
            tactics_list = tactics if isinstance(tactics, list) else []
            for i, item in enumerate(evidence):
                if not isinstance(item, dict):
                    errors.append(f"{prefix}evidence_span item at index {i} must be a dictionary.")
                    continue
                if "tactic" not in item or "evidence" not in item:
                    errors.append(f"{prefix}evidence_span item at index {i} must have 'tactic' and 'evidence' keys.")
                    continue
                t = item["tactic"]
                ev = item["evidence"]
                if not isinstance(t, str) or t not in self.allowed_tactics:
                    errors.append(f"{prefix}evidence_span[{i}] references invalid tactic '{t}'.")
                if t not in tactics_list:
                    errors.append(f"{prefix}evidence_span[{i}] references tactic '{t}' not listed in 'tactics'.")
                if not isinstance(ev, str) or not ev.strip():
                    errors.append(f"{prefix}evidence_span[{i}] has empty or non-string evidence.")
                elif ev not in text_str:
                    errors.append(
                        f"{prefix}evidence_span[{i}] text '{ev}' is not a verbatim substring of 'text'."
                    )

        # 10. requested_action enum
        ra = record.get("requested_action")
        if ra not in self._allowed_actions:
            errors.append(f"{prefix}Invalid requested_action '{ra}'. Allowed: {sorted(self._allowed_actions)}")

        # 11. target_asset enum
        ta = record.get("target_asset")
        if ta not in self._allowed_assets:
            errors.append(f"{prefix}Invalid target_asset '{ta}'. Allowed: {sorted(self._allowed_assets)}")

        # 12. urgency_level enum
        ul = record.get("urgency_level")
        if ul not in self._allowed_urgency:
            errors.append(f"{prefix}Invalid urgency_level '{ul}'. Allowed: {sorted(self._allowed_urgency)}")

        # 13. impersonated_entity enum
        ie = record.get("impersonated_entity")
        if ie not in self._allowed_entities:
            errors.append(f"{prefix}Invalid impersonated_entity '{ie}'. Allowed: {sorted(self._allowed_entities)}")

        # 14. Boolean flags
        for bool_field in ["has_url", "has_phone_number", "has_payment_request"]:
            val = record.get(bool_field)
            if not isinstance(val, (bool, np.bool_)):
                errors.append(f"{prefix}'{bool_field}' must be a boolean (True/False), found {type(val).__name__}.")

        # 15. urls list & URL parseability (no network visits)
        urls = record.get("urls")
        if not isinstance(urls, list):
            errors.append(f"{prefix}'urls' must be a list of strings.")
        else:
            for u in urls:
                if not isinstance(u, str):
                    errors.append(f"{prefix}'urls' contains non-string entry: {u}")
                else:
                    parsed = urlparse(u)
                    if not parsed.scheme and not parsed.netloc and not parsed.path:
                        errors.append(f"{prefix}URL '{u}' could not be parsed.")

        # 16. source_reference non-empty string
        sr = record.get("source_reference")
        if not isinstance(sr, str) or not sr.strip():
            errors.append(f"{prefix}'source_reference' must be a non-empty string.")

        # 17. collection_date format validation (YYYY-MM-DD)
        cdate = record.get("collection_date")
        if not isinstance(cdate, str):
            errors.append(f"{prefix}'collection_date' must be a string formatted as YYYY-MM-DD.")
        else:
            try:
                datetime.strptime(cdate, "%Y-%m-%d")
            except ValueError:
                errors.append(f"{prefix}'collection_date' '{cdate}' does not match format YYYY-MM-DD.")

        # 18. label_confidence enum
        lc = record.get("label_confidence")
        if lc not in self._allowed_confidence:
            errors.append(f"{prefix}Invalid label_confidence '{lc}'. Allowed: {sorted(self._allowed_confidence)}")

        # 19. annotator_id non-empty string
        ann = record.get("annotator_id")
        if not isinstance(ann, str) or not ann.strip():
            errors.append(f"{prefix}'annotator_id' must be a non-empty string.")

        # 20. pattern_group_id non-empty string (critical for leakage prevention)
        pg_id = record.get("pattern_group_id")
        if not isinstance(pg_id, str) or not pg_id.strip():
            errors.append(f"{prefix}'pattern_group_id' is required and must be a non-empty string.")

        # 21. known_unknown_status enum
        kus = record.get("known_unknown_status")
        if kus not in self._allowed_status:
            errors.append(f"{prefix}Invalid known_unknown_status '{kus}'. Allowed: {sorted(self._allowed_status)}")

        # 22. notes optional string
        notes = record.get("notes")
        if notes is not None and not isinstance(notes, str):
            errors.append(f"{prefix}'notes' must be a string or null.")

        return errors

    def validate_dataset(
        self, data: Union[Iterable[Dict[str, Any]], pd.DataFrame]
    ) -> ValidationResult:
        """Validates an entire dataset collection.

        Args:
            data: List of dict records or a pandas DataFrame.

        Returns:
            ValidationResult containing pass/fail state and all error descriptions.
        """
        all_errors: List[str] = []
        seen_sample_ids: Set[str] = set()

        if isinstance(data, pd.DataFrame):
            records = data.to_dict(orient="records")
        else:
            records = list(data)

        for idx, rec in enumerate(records):
            s_id = rec.get("sample_id")
            if s_id in seen_sample_ids:
                all_errors.append(
                    f"Duplicate sample_id '{s_id}' found at row {idx} (previously seen)."
                )
            elif s_id:
                seen_sample_ids.add(s_id)

            record_errors = self.validate_record(rec, record_idx=idx)
            all_errors.extend(record_errors)

        return ValidationResult(
            is_valid=(len(all_errors) == 0),
            errors=all_errors,
            sample_count=len(records),
        )
