"""Text and input preprocessing module for ScamShield AI."""

from .cleaner import clean_text
from .schemas import PreprocessedMessage, ExtractedEntities, TextFeatures
from .normalize import (
    normalize_unicode,
    normalize_whitespace,
    build_normalized_text,
    build_analysis_text,
)
from .extract_entities import (
    extract_urls,
    extract_emails,
    extract_phone_numbers,
    extract_currencies,
    extract_all_entities,
)
from .extract_features import (
    extract_text_features,
    is_otp_related,
    count_emojis,
    analyze_punctuation_repetition,
    has_suspicious_unicode,
)
from .preprocess_message import (
    preprocess_message,
    preprocess_record,
    preprocess_dataset_file,
)

__all__ = [
    "clean_text",
    "PreprocessedMessage",
    "ExtractedEntities",
    "TextFeatures",
    "normalize_unicode",
    "normalize_whitespace",
    "build_normalized_text",
    "build_analysis_text",
    "extract_urls",
    "extract_emails",
    "extract_phone_numbers",
    "extract_currencies",
    "extract_all_entities",
    "extract_text_features",
    "is_otp_related",
    "count_emojis",
    "analyze_punctuation_repetition",
    "has_suspicious_unicode",
    "preprocess_message",
    "preprocess_record",
    "preprocess_dataset_file",
]
