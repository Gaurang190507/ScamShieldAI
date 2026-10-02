"""Robust, pathlib-based dataset loader and exporter supporting JSONL and CSV formats."""

import json
from pathlib import Path
from typing import Union, List, Dict, Any, Optional
import pandas as pd

from .dataset_validator import DatasetValidator, ValidationResult


class DatasetValidationError(Exception):
    """Raised when dataset fails schema or controlled vocabulary validation."""

    def __init__(self, validation_result: ValidationResult):
        self.validation_result = validation_result
        super().__init__(validation_result.summary())


def _deserialize_csv_field(val: Any, default_type: type = list) -> Any:
    """Safely decodes JSON strings stored inside CSV columns."""
    if isinstance(val, str):
        trimmed = val.strip()
        if (trimmed.startswith("[") and trimmed.endswith("]")) or (
            trimmed.startswith("{") and trimmed.endswith("}")
        ):
            try:
                return json.loads(trimmed)
            except json.JSONDecodeError:
                return val
    if pd.isna(val) or val is None:
        return default_type()
    return val


def load_dataset(
    file_path: Union[str, Path],
    validate: bool = True,
    validator: Optional[DatasetValidator] = None,
) -> pd.DataFrame:
    """Loads a ScamShield AI dataset from disk (.jsonl or .csv) without mutating source data.

    Args:
        file_path: Path to dataset file.
        validate: Whether to execute strict schema validation against loaded records.
        validator: Optional customized DatasetValidator instance.

    Returns:
        pd.DataFrame containing loaded samples with preserved types.

    Raises:
        FileNotFoundError: If the specified file does not exist.
        ValueError: If unsupported file format is provided.
        DatasetValidationError: If validation fails and validate is True.
    """
    path = Path(file_path).resolve()
    if not path.is_file():
        raise FileNotFoundError(f"Dataset file not found at path: {path}")

    suffix = path.suffix.lower()
    records: List[Dict[str, Any]] = []

    if suffix == ".jsonl":
        with open(path, "r", encoding="utf-8") as f:
            for line_num, line in enumerate(f, start=1):
                clean_line = line.strip()
                if not clean_line:
                    continue
                try:
                    records.append(json.loads(clean_line))
                except json.JSONDecodeError as e:
                    raise ValueError(f"Malformed JSON on line {line_num} in {path.name}: {e}")

    elif suffix == ".csv":
        raw_df = pd.read_csv(path, keep_default_na=False)
        raw_records = raw_df.to_dict(orient="records")
        for rec in raw_records:
            # Safely unpack structured JSON fields from CSV strings
            rec["tactics"] = _deserialize_csv_field(rec.get("tactics", []), list)
            rec["evidence_spans"] = _deserialize_csv_field(rec.get("evidence_spans", []), list)
            rec["urls"] = _deserialize_csv_field(rec.get("urls", []), list)
            # Ensure boolean representations from CSV
            for b_col in ["has_url", "has_phone_number", "has_payment_request"]:
                if b_col in rec:
                    v = rec[b_col]
                    if isinstance(v, str):
                        rec[b_col] = v.strip().lower() in ("true", "1", "yes")
                    elif isinstance(v, (int, float)):
                        rec[b_col] = bool(v)
            records.append(rec)
    else:
        raise ValueError(
            f"Unsupported dataset format '{suffix}'. Supported formats are: .jsonl, .csv"
        )

    # Schema validation
    if validate:
        v = validator or DatasetValidator()
        result = v.validate_dataset(records)
        if not result.is_valid:
            raise DatasetValidationError(result)

    return pd.DataFrame(records)


def save_dataset(
    df: pd.DataFrame,
    file_path: Union[str, Path],
    format: str = "jsonl",
    validate: bool = True,
    validator: Optional[DatasetValidator] = None,
) -> Path:
    """Exports dataset records cleanly to disk without modifying the input DataFrame.

    Args:
        df: DataFrame containing dataset records.
        file_path: Output target path.
        format: Export format ('jsonl' or 'csv').
        validate: Whether to validate records prior to writing.
        validator: Optional custom validator.

    Returns:
        Path object pointing to the written file.
    """
    path = Path(file_path).resolve()
    path.parent.mkdir(parents=True, exist_ok=True)
    records = df.to_dict(orient="records")

    if validate:
        v = validator or DatasetValidator()
        result = v.validate_dataset(records)
        if not result.is_valid:
            raise DatasetValidationError(result)

    fmt = format.lower().lstrip(".")
    if fmt == "jsonl":
        with open(path, "w", encoding="utf-8") as f:
            for rec in records:
                f.write(json.dumps(rec, ensure_ascii=False) + "\n")
    elif fmt == "csv":
        csv_records = []
        for r in records:
            r_copy = dict(r)
            r_copy["tactics"] = json.dumps(r_copy.get("tactics", []), ensure_ascii=False)
            r_copy["evidence_spans"] = json.dumps(r_copy.get("evidence_spans", []), ensure_ascii=False)
            r_copy["urls"] = json.dumps(r_copy.get("urls", []), ensure_ascii=False)
            csv_records.append(r_copy)
        pd.DataFrame(csv_records).to_csv(path, index=False, encoding="utf-8")
    else:
        raise ValueError(f"Unsupported format '{format}'. Supported formats: 'jsonl', 'csv'.")

    return path
