"""Data structures and schemas for text preprocessing and deterministic feature extraction."""

from dataclasses import dataclass, field, asdict
from typing import List, Dict, Any, Optional


@dataclass
class ExtractedEntities:
    """Entities extracted deterministically from raw message text."""
    urls: List[str] = field(default_factory=list)
    phone_numbers: List[str] = field(default_factory=list)
    emails: List[str] = field(default_factory=list)
    currency_mentions: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class TextFeatures:
    """Observable numerical, structural, and indicator features extracted deterministically."""
    # Text length & character statistics
    character_count: int = 0
    word_count: int = 0
    digit_count: int = 0
    uppercase_count: int = 0
    uppercase_ratio: float = 0.0
    digit_ratio: float = 0.0
    exclamation_count: int = 0
    question_mark_count: int = 0
    special_character_count: int = 0
    line_count: int = 1
    emoji_count: int = 0

    # Entity existence & frequency flags
    has_url: bool = False
    url_count: int = 0

    has_phone_number: bool = False
    phone_count: int = 0

    has_email: bool = False
    email_count: int = 0

    has_currency: bool = False
    currency_count: int = 0
    amount_values: List[float] = field(default_factory=list)

    # Behavioral indicators (features only - not labels)
    otp_related: bool = False
    has_repeated_punctuation: bool = False
    max_consecutive_punctuation: int = 0
    repeated_punctuation_count: int = 0
    has_suspicious_unicode: bool = False

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class PreprocessedMessage:
    """Complete preprocessed message record preserving authoritative raw text and features."""
    sample_id: str
    text: str
    normalized_text: str
    analysis_text: str
    features: TextFeatures
    entities: ExtractedEntities

    def to_dict(self) -> Dict[str, Any]:
        return {
            "sample_id": self.sample_id,
            "text": self.text,
            "normalized_text": self.normalized_text,
            "analysis_text": self.analysis_text,
            "features": self.features.to_dict(),
            "entities": self.entities.to_dict(),
        }
