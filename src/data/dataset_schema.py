"""Dataset schema definitions, enums, controlled vocabularies, and column metadata."""

from enum import Enum
from typing import Set, List, Dict, Any


class Label(str, Enum):
    SCAM = "scam"
    NON_SCAM = "non_scam"


class SourceType(str, Enum):
    PUBLIC_DATASET = "public_dataset"
    EXTERNAL_DATASET = "external_dataset"
    OFFICIAL_ADVISORY = "official_advisory"
    OFFICIAL_KNOWLEDGE = "official_knowledge"
    USER_SUBMITTED = "user_submitted"
    MANUALLY_WRITTEN = "manually_written"
    MANUAL_COLLECTION = "manual_collection"
    SYNTHETIC = "synthetic"
    EVALUATION_REFERENCE = "evaluation_reference"
    OTHER = "other"


class ScamCategory(str, Enum):
    PHISHING = "phishing"
    IMPERSONATION = "impersonation"
    EMPLOYMENT = "employment"
    SHOPPING = "shopping"
    INVESTMENT = "investment"
    PAYMENT = "payment"
    ROMANCE = "romance"
    TECHNICAL_SUPPORT = "technical_support"
    GOVERNMENT_IMPERSONATION = "government_impersonation"
    DELIVERY = "delivery"
    ACCOUNT_TAKEOVER = "account_takeover"
    OTHER = "other"
    UNKNOWN = "unknown"
    NONE = "none"


class RequestedAction(str, Enum):
    CLICK_LINK = "click_link"
    SEND_MONEY = "send_money"
    SHARE_OTP = "share_otp"
    SHARE_PASSWORD = "share_password"
    SHARE_BANK_DETAILS = "share_bank_details"
    SHARE_PERSONAL_INFORMATION = "share_personal_information"
    INSTALL_APPLICATION = "install_application"
    CALL_PHONE_NUMBER = "call_phone_number"
    SCAN_QR = "scan_qr"
    DOWNLOAD_FILE = "download_file"
    TRANSFER_CRYPTO = "transfer_crypto"
    REPLY = "reply"
    NONE = "none"
    OTHER = "other"


class TargetAsset(str, Enum):
    MONEY = "money"
    OTP = "otp"
    PASSWORD = "password"
    BANK_ACCOUNT = "bank_account"
    CREDIT_CARD = "credit_card"
    PERSONAL_INFORMATION = "personal_information"
    IDENTITY_DOCUMENT = "identity_document"
    CRYPTO = "crypto"
    DEVICE_ACCESS = "device_access"
    SOCIAL_MEDIA_ACCOUNT = "social_media_account"
    EMAIL_ACCOUNT = "email_account"
    NONE = "none"
    OTHER = "other"


class UrgencyLevel(str, Enum):
    NONE = "none"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    EXTREME = "extreme"


class ImpersonatedEntity(str, Enum):
    BANK = "bank"
    GOVERNMENT = "government"
    POLICE = "police"
    COURIER = "courier"
    EMPLOYER = "employer"
    CUSTOMER_SUPPORT = "customer_support"
    FRIEND = "friend"
    FAMILY_MEMBER = "family_member"
    SOCIAL_MEDIA_PLATFORM = "social_media_platform"
    COMPANY = "company"
    UNKNOWN = "unknown"
    NONE = "none"


class LabelConfidence(str, Enum):
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


class KnownUnknownStatus(str, Enum):
    KNOWN = "known"
    HELD_OUT = "held_out"
    UNKNOWN = "unknown"


# Default controlled vocabulary for tactical indicators (extensible)
DEFAULT_TACTICS: frozenset[str] = frozenset({
    "impersonation",
    "urgency",
    "threat",
    "fear_creation",
    "authority_claim",
    "payment_request",
    "credential_request",
    "otp_request",
    "personal_information_request",
    "account_suspension",
    "verification_request",
    "reward_claim",
    "investment_pressure",
    "job_offer",
    "emotional_manipulation",
    "secrecy_request",
    "romance_manipulation",
    "technical_support_claim",
    "refund_claim",
    "delivery_problem",
    "qr_code_request",
    "remote_access_request",
    "link_redirection",
})

# Mutable runtime registry allowing controlled vocabulary extension
_TACTICS_REGISTRY: Set[str] = set(DEFAULT_TACTICS)


def get_controlled_tactics() -> Set[str]:
    """Returns the current set of recognized scam tactics."""
    return set(_TACTICS_REGISTRY)


def register_tactic(tactic_name: str) -> None:
    """Registers a new tactic into the controlled vocabulary.

    Args:
        tactic_name: Normalized identifier string (e.g., 'ai_deepfake_voice').
    """
    cleaned = tactic_name.strip().lower()
    if not cleaned:
        raise ValueError("Tactic name cannot be empty.")
    _TACTICS_REGISTRY.add(cleaned)


def reset_tactics_registry() -> None:
    """Resets the vocabulary back to default initial tactics."""
    global _TACTICS_REGISTRY
    _TACTICS_REGISTRY = set(DEFAULT_TACTICS)


REQUIRED_COLUMNS: List[str] = [
    "sample_id",
    "text",
    "language",
    "source_type",
    "label",
    "scam_category",
    "tactics",
    "evidence_spans",
    "requested_action",
    "target_asset",
    "urgency_level",
    "impersonated_entity",
    "has_url",
    "urls",
    "has_phone_number",
    "has_payment_request",
    "source_reference",
    "collection_date",
    "label_confidence",
    "annotator_id",
    "pattern_group_id",
    "known_unknown_status",
    "notes",
]
