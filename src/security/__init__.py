"""Security, validation guards, and offline enforcement for ScamShield AI."""

from .guards import (
    ImageDimensionExceededError,
    ImageSizeExceededError,
    InputValidationError,
    InvalidImageFormatError,
    TextLengthExceededError,
    URLCountExceededError,
    URLLengthExceededError,
    UnsafePathError,
    validate_image_bytes,
    validate_image_file_path,
    validate_safe_path,
    validate_text,
    validate_url,
    validate_url_list,
)
from .prompt_defense import (
    detect_prompt_injection,
    sanitize_prompt_user_content,
)

__all__ = [
    "InputValidationError",
    "TextLengthExceededError",
    "URLLengthExceededError",
    "URLCountExceededError",
    "ImageSizeExceededError",
    "ImageDimensionExceededError",
    "InvalidImageFormatError",
    "UnsafePathError",
    "validate_text",
    "validate_url",
    "validate_url_list",
    "validate_image_bytes",
    "validate_image_file_path",
    "validate_safe_path",
    "detect_prompt_injection",
    "sanitize_prompt_user_content",
]
