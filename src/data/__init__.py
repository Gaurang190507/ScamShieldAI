"""ScamShield AI: Dataset infrastructure, schema definitions, validation, and loaders."""

from .dataset_schema import (
    Label,
    SourceType,
    ScamCategory,
    RequestedAction,
    TargetAsset,
    UrgencyLevel,
    ImpersonatedEntity,
    LabelConfidence,
    KnownUnknownStatus,
    DEFAULT_TACTICS,
    REQUIRED_COLUMNS,
)
from .dataset_validator import DatasetValidator, ValidationResult
from .data_loader import load_dataset, save_dataset
from .dataset_stats import generate_dataset_statistics
from .duplicate_detector import detect_duplicates, DuplicateReport
from .leakage_split import group_leakage_split
from .ingest_uci_sms import ingest_uci_sms
from .create_pilot_selection import select_pilot_cohort
from .create_pilot_dataset import write_and_validate_pilot_dataset

__all__ = [
    "Label",
    "SourceType",
    "ScamCategory",
    "RequestedAction",
    "TargetAsset",
    "UrgencyLevel",
    "ImpersonatedEntity",
    "LabelConfidence",
    "KnownUnknownStatus",
    "DEFAULT_TACTICS",
    "REQUIRED_COLUMNS",
    "DatasetValidator",
    "ValidationResult",
    "load_dataset",
    "save_dataset",
    "generate_dataset_statistics",
    "detect_duplicates",
    "DuplicateReport",
    "group_leakage_split",
    "ingest_uci_sms",
    "select_pilot_cohort",
    "write_and_validate_pilot_dataset",
]
