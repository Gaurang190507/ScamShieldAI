"""End-to-end OCR Text Extractor and Image Case Assessment Pipeline for ScamShield AI.

Coordinates:
1. Local image loading and validation.
2. Local OCR text extraction (raw text preserved).
3. Conservative text normalization.
4. Deterministic entity extraction (URLs, phones, emails, currency, OTP).
5. Downstream ScamShield AI pipeline evaluation (Phases 3, 4, 6, 7, and 8).
6. Forensic audit trail certifying local/offline processing and zero network access.
"""

from pathlib import Path
import re
from typing import Any, Dict, List, Optional, Tuple, Union

from .image_loader import (
    CorruptImageError,
    EmptyImageError,
    ImageLoadError,
    ImageNotFoundError,
    InvalidImageFormatError,
    load_and_validate_image,
)
from .ocr_engine import AutoOCREngine, BaseOCREngine
from .schemas import (
    ExtractedEntitiesResult,
    ImageCaseAssessmentResult,
    ImageInputMetadata,
    OCRAuditTrail,
    OCRResult,
)
from .text_postprocessor import normalize_ocr_text

from src.aggregation.pipeline import CaseAssessmentPipeline
from src.preprocessing.extract_entities import (
    extract_currencies,
    extract_emails,
    extract_phone_numbers,
    extract_urls,
)


# Deterministic pattern for identifying OTP tokens and explicit verification requests
OTP_MENTION_REGEX = re.compile(
    r"(?:"
    r"\b(?:otp|one[- ]time password|one[- ]time pin|verification code|security code)\b"
    r"|\b(?:code|pin|otp)\s*(?:is|:)?\s*\d{4,8}\b"
    r")",
    re.IGNORECASE,
)


def extract_otp_mentions(text: str) -> List[str]:
    """Extracts OTP and one-time verification code mentions deterministically."""
    if not isinstance(text, str):
        return []
    mentions: List[str] = []
    for m in OTP_MENTION_REGEX.finditer(text):
        clean = m.group(0).strip()
        if clean not in mentions:
            mentions.append(clean)
    return mentions


def extract_ocr_entities(text: str) -> ExtractedEntitiesResult:
    """Extracts all canonical entities from normalized OCR text deterministically.

    Reuses existing ScamShield preprocessing extractors:
    - URLs
    - Emails
    - Phone numbers (with URL/email masking)
    - Currency and monetary mentions
    - OTP mentions
    """
    if not text:
        return ExtractedEntitiesResult()

    urls = extract_urls(text)
    emails = extract_emails(text)
    phones = extract_phone_numbers(text, urls=urls, emails=emails)
    currencies, _ = extract_currencies(text)
    otps = extract_otp_mentions(text)

    return ExtractedEntitiesResult(
        urls=urls,
        phone_numbers=phones,
        email_addresses=emails,
        currency_mentions=currencies,
        otp_mentions=otps,
    )


class OCRTextExtractor:
    """Local, offline extractor converting image files into normalized text and entities."""

    def __init__(self, ocr_engine: Optional[BaseOCREngine] = None):
        """Initializes extractor with specified or default AutoOCREngine."""
        self.engine = ocr_engine or AutoOCREngine()

    def extract(
        self,
        image_path: Union[str, Path],
    ) -> Tuple[ImageInputMetadata, OCRResult, ExtractedEntitiesResult, OCRAuditTrail]:
        """Loads image, runs local OCR, normalizes text, and extracts entities.

        Args:
            image_path: Path to candidate image on disk.

        Returns:
            Tuple of (ImageInputMetadata, OCRResult, ExtractedEntitiesResult, OCRAuditTrail).
        """
        path = Path(image_path).resolve()
        warnings: List[str] = []
        errors: List[str] = []

        # 1. Load and validate image
        try:
            pil_image, img_meta = load_and_validate_image(path)
        except ImageNotFoundError as e:
            dummy_meta = ImageInputMetadata(
                filename=path.name,
                filepath=str(path),
                format="unknown",
                width=0,
                height=0,
                file_size_bytes=0,
            )
            ocr_res = OCRResult(
                success=False,
                status="invalid_image",
                engine=self.engine.engine_name,
                errors=[f"Image not found: {e}"],
            )
            audit = OCRAuditTrail(
                engine=self.engine.engine_name,
                success=False,
                raw_text_preserved=False,
            )
            return dummy_meta, ocr_res, ExtractedEntitiesResult(), audit

        except (InvalidImageFormatError, EmptyImageError, CorruptImageError, ImageLoadError) as e:
            dummy_meta = ImageInputMetadata(
                filename=path.name,
                filepath=str(path),
                format=path.suffix.lstrip(".").lower() or "unknown",
                width=0,
                height=0,
                file_size_bytes=path.stat().st_size if path.exists() else 0,
            )
            ocr_res = OCRResult(
                success=False,
                status="invalid_image",
                engine=self.engine.engine_name,
                errors=[f"Image validation error: {e}"],
            )
            audit = OCRAuditTrail(
                engine=self.engine.engine_name,
                success=False,
                raw_text_preserved=False,
            )
            return dummy_meta, ocr_res, ExtractedEntitiesResult(), audit

        # 2. Execute local OCR extraction
        raw_text, confidence, engine_warnings, engine_errors = self.engine.extract_text(
            pil_image, image_path=path
        )
        warnings.extend(engine_warnings)
        errors.extend(engine_errors)

        # 3. Handle engine failure states
        if "engine_unavailable" in errors:
            ocr_res = OCRResult(
                success=False,
                status="engine_unavailable",
                engine=self.engine.engine_name,
                warnings=warnings,
                errors=errors,
            )
            audit = OCRAuditTrail(
                engine=self.engine.engine_name,
                success=False,
                raw_text_preserved=False,
            )
            return img_meta, ocr_res, ExtractedEntitiesResult(), audit

        # 4. Handle empty extraction vs success
        if not raw_text.strip():
            ocr_res = OCRResult(
                success=True,
                status="no_text_detected",
                engine=self.engine.engine_name,
                raw_text="",
                normalized_text="",
                confidence=confidence,
                warnings=warnings,
                errors=errors,
            )
            audit = OCRAuditTrail(
                engine=self.engine.engine_name,
                success=True,
                raw_text_preserved=True,
            )
            return img_meta, ocr_res, ExtractedEntitiesResult(), audit

        # 5. Success with text
        norm_text = normalize_ocr_text(raw_text)
        ocr_res = OCRResult(
            success=True,
            status="success",
            engine=self.engine.engine_name,
            raw_text=raw_text,
            normalized_text=norm_text,
            confidence=confidence,
            warnings=warnings,
            errors=errors,
        )

        # 6. Extract entities on normalized text
        entities = extract_ocr_entities(norm_text)

        # 7. Forensic audit trail
        audit = OCRAuditTrail(
            engine=self.engine.engine_name,
            success=True,
            raw_text_preserved=True,
            network_access=False,
            external_service=False,
            spatial_coordinates_available=False,
        )

        return img_meta, ocr_res, entities, audit


class ImageCaseAssessmentPipeline:
    """Unified pipeline connecting image ingestion, OCR, and the ScamShield AI engine."""

    def __init__(
        self,
        extractor: Optional[OCRTextExtractor] = None,
        downstream_pipeline: Optional[CaseAssessmentPipeline] = None,
        enable_semantic: bool = True,
    ):
        """Initializes image evaluation pipeline."""
        self.extractor = extractor or OCRTextExtractor()
        self.pipeline = downstream_pipeline or CaseAssessmentPipeline(
            enable_semantic=enable_semantic
        )

    def analyze_image(
        self,
        image_path: Union[str, Path],
        sample_id: Optional[str] = None,
    ) -> ImageCaseAssessmentResult:
        """Evaluates a screenshot/image end-to-end through ScamShield AI.

        Args:
            image_path: Path to image file.
            sample_id: Optional sample identifier. Defaults to image filename.

        Returns:
            Structured ImageCaseAssessmentResult.
        """
        path = Path(image_path).resolve()
        sid = sample_id or path.stem

        # Step 1: Extract OCR text and entities
        img_meta, ocr_res, entities, audit = self.extractor.extract(path)
        warnings: List[str] = list(ocr_res.warnings)

        assessment_dict: Optional[Dict[str, Any]] = None

        # Step 2: Route through downstream ScamShield pipeline
        if ocr_res.status == "success":
            downstream_res = self.pipeline.analyze(
                text=ocr_res.normalized_text,
                sample_id=sid,
                urls=entities.urls,
            )
            assessment_dict = downstream_res.to_dict()

        elif ocr_res.status == "no_text_detected":
            # Image is valid but contains no readable text -> insufficient evidence
            downstream_res = self.pipeline.analyze(
                text="",
                sample_id=sid,
                urls=[],
            )
            assessment_dict = downstream_res.to_dict()
            warnings.append("OCR completed successfully but no text was identified in the image.")

        elif ocr_res.status == "engine_unavailable":
            warnings.append(
                "Downstream ScamShield analysis could not be executed because no local OCR engine is available."
            )

        elif ocr_res.status == "invalid_image":
            warnings.append(
                "Downstream ScamShield analysis skipped due to invalid or unreadable image file."
            )

        return ImageCaseAssessmentResult(
            input=img_meta,
            ocr=ocr_res,
            entities=entities,
            assessment=assessment_dict,
            warnings=warnings,
            audit=audit,
        )
