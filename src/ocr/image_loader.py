"""Deterministic image validation and loading for ScamShield AI Phase 9A.

Supports local image formats:
.png, .jpg, .jpeg, .webp, .bmp, .tiff, .tif

Strictly validates:
- File presence and readability
- Non-zero file size
- Allowed format extension and decoded image headers
- Dimension integrity (width > 0, height > 0)
- Image data non-corruption

Zero network calls. Operates purely locally via Pillow.
"""

from pathlib import Path
from typing import Tuple, Union
from PIL import Image, UnidentifiedImageError

from .schemas import ImageInputMetadata


SUPPORTED_EXTENSIONS = {
    ".png",
    ".jpg",
    ".jpeg",
    ".webp",
    ".bmp",
    ".tiff",
    ".tif",
}

SUPPORTED_PIL_FORMATS = {
    "PNG",
    "JPEG",
    "WEBP",
    "BMP",
    "TIFF",
}


class ImageLoadError(Exception):
    """Base exception for image loading failures."""
    pass


class ImageNotFoundError(ImageLoadError):
    """Raised when the specified image file does not exist."""
    pass


class InvalidImageFormatError(ImageLoadError):
    """Raised when the image format is unsupported."""
    pass


class EmptyImageError(ImageLoadError):
    """Raised when the image file is 0 bytes."""
    pass


class CorruptImageError(ImageLoadError):
    """Raised when the image file cannot be decoded or is corrupt."""
    pass


def load_and_validate_image(
    image_path: Union[str, Path],
) -> Tuple[Image.Image, ImageInputMetadata]:
    """Loads and strictly validates a local image file.

    Args:
        image_path: Path to the image file on disk.

    Returns:
        Tuple of (PIL Image instance, ImageInputMetadata).

    Raises:
        ImageNotFoundError: If file does not exist or is not a file.
        EmptyImageError: If file has 0 bytes.
        InvalidImageFormatError: If file extension or decoded format is unsupported.
        CorruptImageError: If file cannot be decoded or has invalid dimensions.
    """
    path = Path(image_path).resolve()

    if not path.exists() or not path.is_file():
        raise ImageNotFoundError(f"Image file not found: {path}")

    # Check extension
    ext = path.suffix.lower()
    if ext not in SUPPORTED_EXTENSIONS:
        raise InvalidImageFormatError(
            f"Unsupported file extension '{ext}'. Supported: {sorted(list(SUPPORTED_EXTENSIONS))}"
        )

    # Check file size
    size_bytes = path.stat().st_size
    if size_bytes == 0:
        raise EmptyImageError(f"Image file is empty (0 bytes): {path}")

    # Open with PIL and decode
    try:
        # Load and convert to RGB
        with Image.open(path) as img:
            img_format = (img.format or "").upper()
            if img_format not in SUPPORTED_PIL_FORMATS and ext not in SUPPORTED_EXTENSIONS:
                raise InvalidImageFormatError(f"Decoded format '{img_format}' is unsupported.")

            width, height = img.size
            if width <= 0 or height <= 0:
                raise CorruptImageError(f"Invalid image dimensions: {width}x{height}")

            # Verify image integrity by forcing raster loading
            img.load()
            # Create a separate copy to keep in memory once file context exits
            loaded_img = img.copy()

    except (UnidentifiedImageError, OSError, SyntaxError) as e:
        raise CorruptImageError(f"Failed to decode image data from {path}: {e}") from e

    metadata = ImageInputMetadata(
        filename=path.name,
        filepath=str(path),
        format=img_format.lower() if img_format else ext.lstrip(".").lower(),
        width=width,
        height=height,
        file_size_bytes=size_bytes,
    )

    return loaded_img, metadata
