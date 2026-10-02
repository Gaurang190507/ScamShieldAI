"""ScamShield AI — Phase 9A: Screenshot Ingestion, OCR & Existing Pipeline Integration.

Provides offline, auditable image loading, optical character recognition,
conservative text normalization, and downstream ScamShield risk evaluation.
"""

from .schemas import (
    ImageInputMetadata,
    OCRResult,
    ExtractedEntitiesResult,
    OCRAuditTrail,
    ImageCaseAssessmentResult,
)
from .image_loader import (
    load_and_validate_image,
    ImageLoadError,
    ImageNotFoundError,
    InvalidImageFormatError,
    EmptyImageError,
    CorruptImageError,
    SUPPORTED_EXTENSIONS,
)
from .text_postprocessor import normalize_ocr_text
from .ocr_engine import (
    BaseOCREngine,
    TesseractOCREngine,
    FixtureOCREngine,
    AutoOCREngine,
)
from .extractor import (
    OCRTextExtractor,
    ImageCaseAssessmentPipeline,
    extract_ocr_entities,
    extract_otp_mentions,
)

__all__ = [
    "ImageInputMetadata",
    "OCRResult",
    "ExtractedEntitiesResult",
    "OCRAuditTrail",
    "ImageCaseAssessmentResult",
    "load_and_validate_image",
    "ImageLoadError",
    "ImageNotFoundError",
    "InvalidImageFormatError",
    "EmptyImageError",
    "CorruptImageError",
    "SUPPORTED_EXTENSIONS",
    "normalize_ocr_text",
    "BaseOCREngine",
    "TesseractOCREngine",
    "FixtureOCREngine",
    "AutoOCREngine",
    "OCRTextExtractor",
    "ImageCaseAssessmentPipeline",
    "extract_ocr_entities",
    "extract_otp_mentions",
]
