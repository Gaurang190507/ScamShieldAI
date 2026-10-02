"""Defensive input validation and resource boundary guards for ScamShield AI.

Features:
- Validates text length, URL length, URL count, image file size, and image dimensions.
- Protects against:
  1. Denial of Service (DoS) via massive text payloads or URL flooding.
  2. Regular Expression CPU exhaustion (ReDoS) in tactical pattern matching.
  3. Decompression bombs and memory exhaustion from high-resolution images.
  4. Path traversal, Windows UNC network injection, null bytes, and reserved device names.
  5. Executable, local, and pseudo URL schemes (javascript:, file:, data:, blob:).
- Provides non-crashing validation interfaces returning structured diagnostics.
"""

import io
import os
from pathlib import Path
import re
from typing import Any, Dict, List, Optional, Tuple, Union
from PIL import Image

from src.config.runtime_config import RuntimeConfig, get_runtime_config


class InputValidationError(ValueError):
    """Base exception for user input validation violations."""
    pass


class TextLengthExceededError(InputValidationError):
    """Raised when input text exceeds maximum length boundary."""
    pass


class URLLengthExceededError(InputValidationError):
    """Raised when a URL exceeds maximum length boundary."""
    pass


class URLCountExceededError(InputValidationError):
    """Raised when the number of parsed URLs exceeds safety limit."""
    pass


class ImageSizeExceededError(InputValidationError):
    """Raised when an uploaded image exceeds byte size boundary."""
    pass


class ImageDimensionExceededError(InputValidationError):
    """Raised when image pixel dimensions exceed decompression safety boundary."""
    pass


class InvalidImageFormatError(InputValidationError):
    """Raised when image format or extension is not in permitted list."""
    pass


class UnsafePathError(InputValidationError):
    """Raised when a file path violates filesystem safety invariants (UNC, traversal, nulls)."""
    pass


# Windows DOS reserved device names that cause driver hangs or errors
_WINDOWS_RESERVED_DEVICES = {
    "CON", "PRN", "AUX", "NUL",
    "COM1", "COM2", "COM3", "COM4", "COM5", "COM6", "COM7", "COM8", "COM9",
    "LPT1", "LPT2", "LPT3", "LPT4", "LPT5", "LPT6", "LPT7", "LPT8", "LPT9",
}

# Dangerous URL schemes that execute script or access local system resources
_DANGEROUS_URL_SCHEMES = {"javascript", "vbscript", "data", "file", "blob", "about"}


def validate_safe_path(
    path: Union[str, Path],
    allowed_base_dirs: Optional[List[Path]] = None,
    allowed_extensions: Optional[Tuple[str, ...]] = None,
    must_exist: bool = False,
) -> Tuple[bool, Optional[str]]:
    """Strictly validates a file path against traversal, UNC network injection, and device names.

    Args:
        path: Path string or Path object.
        allowed_base_dirs: Optional list of directories within which the path must resolve.
        allowed_extensions: Optional tuple of permitted file extensions (e.g. ('.png', '.jpg')).
        must_exist: Whether the file must already exist on disk.

    Returns:
        Tuple of (is_valid: bool, error_message: Optional[str]).
    """
    if path is None:
        return False, "Path is None."

    raw_str = str(path).strip()
    if not raw_str:
        return False, "Path is empty."

    # 1. Null Byte Guard
    if "\x00" in raw_str:
        return False, "Path contains invalid null byte (\\x00)."

    # 2. UNC / Network Share Guard (Prevents Windows SMB outbound hangs/NTLM leaks)
    if raw_str.startswith(("\\\\", "//")) or bool(re.match(r"^[\\/]{2,}", raw_str)):
        return False, f"UNC network paths are forbidden (SMB/network injection guard): '{raw_str}'."

    # 3. Windows Reserved DOS Device Names Guard
    try:
        p_obj = Path(raw_str)
        if p_obj.stem.upper() in _WINDOWS_RESERVED_DEVICES or any(
            part.upper() in _WINDOWS_RESERVED_DEVICES for part in p_obj.parts
        ):
            return False, f"Windows reserved device names are forbidden: '{raw_str}'."
    except Exception as e:
        return False, f"Malformed path syntax: {e}"

    # 4. Directory Traversal Guard
    if ".." in p_obj.parts or bool(re.search(r"(?:^|[\\/])\.\.(?:[\\/]|$)", raw_str)):
        return False, f"Directory traversal sequences (..) are forbidden: '{raw_str}'."

    # 5. Extension Validation
    if allowed_extensions:
        suffix = p_obj.suffix.lower()
        if suffix not in allowed_extensions:
            allowed_str = ", ".join(allowed_extensions)
            return False, f"Extension '{suffix}' not allowed ({allowed_str})."

    # 6. Existence and Confinement Validation (Safe to resolve now that UNC/traversal are blocked)
    if must_exist or allowed_base_dirs:
        try:
            resolved = p_obj.resolve()
        except Exception as e:
            return False, f"Path resolution error: {e}"

        if must_exist:
            if not resolved.exists():
                return False, f"Image file not found: '{resolved}'"
            if not resolved.is_file():
                return False, f"Target path is not a file: '{resolved}'"

        if allowed_base_dirs:
            is_confined = any(
                resolved.is_relative_to(base.resolve())
                for base in allowed_base_dirs
            )
            if not is_confined:
                return False, f"Path '{resolved}' escapes allowed directory boundaries."

    return True, None


def validate_text(
    text: Optional[str], config: Optional[RuntimeConfig] = None
) -> Tuple[bool, Optional[str]]:
    """Validates message text against configured resource limits and null-byte hazards.

    Args:
        text: Input message string.
        config: Optional runtime configuration override.

    Returns:
        Tuple of (is_valid: bool, error_message: Optional[str]).
    """
    if text is None or not isinstance(text, str):
        return True, None

    # Null Byte Guard
    if "\x00" in text:
        return False, "Input text contains forbidden null bytes (\\x00)."

    cfg = config or get_runtime_config()
    text_len = len(text)
    if text_len > cfg.MAX_TEXT_LENGTH:
        msg = (
            f"Input text length ({text_len:,} characters) exceeds the maximum allowed "
            f"boundary of {cfg.MAX_TEXT_LENGTH:,} characters."
        )
        return False, msg

    return True, None


def validate_url(
    url: Optional[str], config: Optional[RuntimeConfig] = None
) -> Tuple[bool, Optional[str]]:
    """Validates a single URL string against configured length limits and dangerous schemes.

    Args:
        url: Input URL string.
        config: Optional runtime configuration override.

    Returns:
        Tuple of (is_valid: bool, error_message: Optional[str]).
    """
    if url is None or not isinstance(url, str) or not url.strip():
        return True, None

    clean_url = url.strip()

    # Null Byte Guard
    if "\x00" in clean_url:
        return False, "URL contains forbidden null bytes (\\x00)."

    # Dangerous Executable/Local Scheme Guard
    scheme_match = re.match(r"^([a-zA-Z][a-zA-Z0-9+.-]*):", clean_url)
    if scheme_match:
        scheme = scheme_match.group(1).lower()
        if scheme in _DANGEROUS_URL_SCHEMES:
            return (
                False,
                f"URL scheme '{scheme}:' is blocked for security reasons (executable/local scheme).",
            )

    cfg = config or get_runtime_config()
    url_len = len(clean_url)
    if url_len > cfg.MAX_URL_LENGTH:
        msg = (
            f"URL length ({url_len:,} characters) exceeds the maximum allowed "
            f"boundary of {cfg.MAX_URL_LENGTH:,} characters."
        )
        return False, msg

    return True, None


def validate_url_list(
    urls: List[str], config: Optional[RuntimeConfig] = None
) -> Tuple[bool, Optional[str]]:
    """Validates a collection of URLs against count and individual length bounds.

    Args:
        urls: List of URL strings.
        config: Optional runtime configuration override.

    Returns:
        Tuple of (is_valid: bool, error_message: Optional[str]).
    """
    if not urls:
        return True, None

    cfg = config or get_runtime_config()
    count = len(urls)
    if count > cfg.MAX_URL_COUNT:
        msg = (
            f"Total URL count ({count}) exceeds maximum allowed boundary of {cfg.MAX_URL_COUNT} URLs per submission."
        )
        return False, msg

    for i, u in enumerate(urls):
        ok, err = validate_url(u, cfg)
        if not ok:
            return False, f"URL #{i+1} invalid: {err}"

    return True, None


def validate_image_bytes(
    image_bytes: bytes,
    filename: Optional[str] = None,
    config: Optional[RuntimeConfig] = None,
) -> Tuple[bool, Optional[str]]:
    """Defensively checks image bytes for size, format, and dimension safety.

    Args:
        image_bytes: Raw binary image payload.
        filename: Optional uploaded file name.
        config: Optional runtime configuration override.

    Returns:
        Tuple of (is_valid: bool, error_message: Optional[str]).
    """
    if not image_bytes:
        return False, "Image payload is empty (0 bytes)."

    cfg = config or get_runtime_config()
    byte_len = len(image_bytes)

    # 1. Byte Size Check
    if byte_len > cfg.MAX_IMAGE_BYTES:
        mb = byte_len / (1024 * 1024)
        max_mb = cfg.MAX_IMAGE_BYTES / (1024 * 1024)
        return (
            False,
            f"Image file size ({mb:.2f} MB) exceeds maximum allowed boundary of {max_mb:.1f} MB.",
        )

    # 2. File Extension Check (if filename provided)
    if filename:
        suffix = Path(filename).suffix.lower()
        if suffix and suffix not in cfg.ALLOWED_IMAGE_EXTENSIONS:
            allowed = ", ".join(cfg.ALLOWED_IMAGE_EXTENSIONS)
            return (
                False,
                f"Image file extension '{suffix}' is not supported. Allowed formats: {allowed}.",
            )

    # 3. Header & Dimension Check via PIL (safe header inspection)
    try:
        with Image.open(io.BytesIO(image_bytes)) as img:
            fmt = (img.format or "").upper()
            if fmt not in ["PNG", "JPEG", "JPG", "WEBP"]:
                return (
                    False,
                    f"Unsupported image format '{fmt}'. Only PNG, JPEG, and WebP are allowed.",
                )

            w, h = img.size
            if w > cfg.MAX_IMAGE_DIMENSION or h > cfg.MAX_IMAGE_DIMENSION:
                return (
                    False,
                    f"Image dimensions ({w}x{h}) exceed maximum allowed dimension of "
                    f"{cfg.MAX_IMAGE_DIMENSION}x{cfg.MAX_IMAGE_DIMENSION} pixels (decompression bomb guard).",
                )
    except Exception as e:
        return False, f"Malformed or unreadable image file: {e}"

    return True, None


def validate_image_file_path(
    path: Union[str, Path], config: Optional[RuntimeConfig] = None
) -> Tuple[bool, Optional[str]]:
    """Validates an image file path on disk against path safety, file size, and image dimensions."""
    cfg = config or get_runtime_config()

    # Pre-flight Path Security Check (strictly blocks UNC, traversal, nulls, reserved devices)
    safe_ok, safe_err = validate_safe_path(
        path,
        allowed_extensions=cfg.ALLOWED_IMAGE_EXTENSIONS,
        must_exist=True,
    )
    if not safe_ok:
        return False, safe_err

    p = Path(path).resolve()
    size = p.stat().st_size
    if size > cfg.MAX_IMAGE_BYTES:
        mb = size / (1024 * 1024)
        max_mb = cfg.MAX_IMAGE_BYTES / (1024 * 1024)
        return False, f"Image size ({mb:.2f} MB) exceeds limit of {max_mb:.1f} MB."

    try:
        with Image.open(p) as img:
            w, h = img.size
            if w > cfg.MAX_IMAGE_DIMENSION or h > cfg.MAX_IMAGE_DIMENSION:
                return (
                    False,
                    f"Image dimensions ({w}x{h}) exceed maximum allowed limit of "
                    f"{cfg.MAX_IMAGE_DIMENSION}x{cfg.MAX_IMAGE_DIMENSION} pixels.",
                )
    except Exception as e:
        return False, f"Malformed image file: {e}"

    return True, None
