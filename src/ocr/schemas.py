"""Canonical data schemas for ScamShield AI Phase 9A OCR Ingestion & Integration.

Defines structured objects for:
- ImageInputMetadata: File and dimensional properties of the input image.
- OCRResult: Raw and normalized text extracted by the OCR engine, with failure states.
- ExtractedEntitiesResult: Discrete entity classes extracted deterministically from text.
- OCRAuditTrail: Forensic audit verifying local/offline processing and zero external calls.
- ImageCaseAssessmentResult: Complete unified case-level assessment combining OCR + ScamShield.
"""

from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional


@dataclass
class ImageInputMetadata:
    """Metadata describing the input image file."""

    filename: str
    filepath: str
    format: str  # e.g., "png", "jpeg", "webp"
    width: int
    height: int
    file_size_bytes: int

    def to_dict(self) -> Dict[str, Any]:
        """Serializes input metadata to dictionary."""
        return asdict(self)


@dataclass
class OCRResult:
    """Outcome of the optical character recognition extraction stage."""

    success: bool
    status: str  # "success", "no_text_detected", "invalid_image", "engine_unavailable"
    engine: str  # e.g., "tesseract", "fixture_engine"
    language: str = "eng"
    raw_text: str = ""
    normalized_text: str = ""
    confidence: Optional[float] = None  # null if not reliably reported by engine
    warnings: List[str] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        """Serializes OCR result to dictionary."""
        return asdict(self)


@dataclass
class ExtractedEntitiesResult:
    """Entities deterministically extracted from OCR-derived text."""

    urls: List[str] = field(default_factory=list)
    phone_numbers: List[str] = field(default_factory=list)
    email_addresses: List[str] = field(default_factory=list)
    currency_mentions: List[str] = field(default_factory=list)
    otp_mentions: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        """Serializes extracted entities to dictionary."""
        return asdict(self)


@dataclass
class OCRAuditTrail:
    """Forensic audit trail for image and OCR ingestion."""

    source_type: str = "screenshot"
    engine: str = "unknown"
    success: bool = False
    raw_text_preserved: bool = True
    network_access: bool = False  # Guaranteed offline
    external_service: bool = False  # Guaranteed zero external API calls
    spatial_coordinates_available: bool = False  # Explicitly false: text offsets only, no pixel bounding boxes
    timestamp: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )

    def to_dict(self) -> Dict[str, Any]:
        """Serializes audit trail to dictionary."""
        return asdict(self)


@dataclass
class ImageCaseAssessmentResult:
    """Complete end-to-end assessment container combining OCR and downstream ScamShield evaluation."""

    input: ImageInputMetadata
    ocr: OCRResult
    entities: ExtractedEntitiesResult
    assessment: Optional[Dict[str, Any]] = None  # Downstream CaseAssessmentResult.to_dict()
    warnings: List[str] = field(default_factory=list)
    audit: OCRAuditTrail = field(default_factory=OCRAuditTrail)

    def to_dict(self) -> Dict[str, Any]:
        """Serializes complete image assessment result to JSON-compliant dictionary."""
        return {
            "input": self.input.to_dict(),
            "ocr": self.ocr.to_dict(),
            "entities": self.entities.to_dict(),
            "assessment": self.assessment,
            "warnings": self.warnings,
            "audit": self.audit.to_dict(),
        }
