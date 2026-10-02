"""OCR engine adapters and execution interfaces for ScamShield AI Phase 9A.

Implements:
- BaseOCREngine: Abstract contract for optical character recognition.
- TesseractOCREngine: Local Tesseract execution via pytesseract (if installed on host).
- FixtureOCREngine: Deterministic offline fixture provider for reproducible local testing.
- AutoOCREngine: Transparent coordinator selecting local Tesseract or fixture provider,
  and distinctly reporting 'engine_unavailable' if no engine is present.

OPERATIONAL SAFETY:
- 100% offline. Zero network calls, zero external web APIs, zero LLM dependencies.
"""

from abc import ABC, abstractmethod
import hashlib
import io
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple, Union
from PIL import Image


class BaseOCREngine(ABC):
    """Abstract contract for offline OCR engines."""

    @property
    @abstractmethod
    def engine_name(self) -> str:
        """Name identifier of the OCR engine."""
        pass

    @abstractmethod
    def is_available(self) -> bool:
        """Returns True if the engine's binaries/dependencies are installed and operational."""
        pass

    @abstractmethod
    def extract_text(
        self,
        image: Image.Image,
        image_path: Optional[Union[str, Path]] = None,
    ) -> Tuple[str, Optional[float], List[str], List[str]]:
        """Extracts text from an in-memory image.

        Args:
            image: PIL Image instance.
            image_path: Optional path to the image file on disk.

        Returns:
            Tuple of:
            - raw_text: Verbatim extracted text string.
            - confidence: Float confidence in [0.0, 1.0], or None if unavailable.
            - warnings: List of warning strings.
            - errors: List of error strings.
        """
        pass


class TesseractOCREngine(BaseOCREngine):
    """Local Tesseract OCR engine executed via pytesseract."""

    def __init__(self, tesseract_cmd: Optional[str] = None):
        """Initializes Tesseract adapter."""
        self.tesseract_cmd = tesseract_cmd
        self._pytesseract = None
        self._check_availability()

    @property
    def engine_name(self) -> str:
        return "tesseract"

    def _check_availability(self) -> bool:
        try:
            import pytesseract
            self._pytesseract = pytesseract
            if self.tesseract_cmd:
                self._pytesseract.pytesseract.tesseract_cmd = self.tesseract_cmd
            # Verify executable works
            _ = self._pytesseract.get_tesseract_version()
            return True
        except Exception:
            self._pytesseract = None
            return False

    def is_available(self) -> bool:
        return self._pytesseract is not None

    def extract_text(
        self,
        image: Image.Image,
        image_path: Optional[Union[str, Path]] = None,
    ) -> Tuple[str, Optional[float], List[str], List[str]]:
        if not self.is_available():
            return "", None, ["Tesseract OCR engine is not installed or available on this system."], ["engine_unavailable"]

        try:
            raw_text = self._pytesseract.image_to_string(image, lang="eng")
            return raw_text, None, [], []
        except Exception as e:
            return "", None, [f"Tesseract extraction error: {e}"], [str(e)]


class FixtureOCREngine(BaseOCREngine):
    """Deterministic offline fixture adapter mapping image hashes or paths to known raw text.

    Ensures 100% reproducible testing and evaluation on standard test fixtures
    even in environments without native system Tesseract binaries.
    """

    def __init__(self, manifest_path: Optional[Union[str, Path]] = None):
        """Initializes fixture registry and loads manifest if present."""
        self._path_registry: Dict[str, str] = {}
        self._hash_registry: Dict[str, str] = {}

        if manifest_path is None:
            default_manifest = (
                Path(__file__).resolve().parents[2] / "tests" / "fixtures" / "images" / "manifest.json"
            )
            if default_manifest.is_file():
                manifest_path = default_manifest

        if manifest_path and Path(manifest_path).is_file():
            self.load_manifest(manifest_path)

    def load_manifest(self, manifest_path: Union[str, Path]) -> None:
        """Loads and registers fixtures from a manifest JSON file."""
        import json
        m_path = Path(manifest_path).resolve()
        with open(m_path, "r", encoding="utf-8") as f:
            data = json.load(f)
            for fname, item in data.items():
                text = item.get("ground_truth_text", "")
                fpath = item.get("filepath")
                self.register_fixture(raw_text=text, image_path=fpath or fname)

    @property
    def engine_name(self) -> str:
        return "fixture_engine"

    def is_available(self) -> bool:
        return True

    @staticmethod
    def compute_image_hash(image: Image.Image) -> str:
        """Computes deterministic SHA256 hash of image raster bytes."""
        # Convert image to standardized RGB bytes
        rgb_img = image.convert("RGB")
        buf = io.BytesIO()
        rgb_img.save(buf, format="PNG")
        return hashlib.sha256(buf.getvalue()).hexdigest()

    def register_fixture(
        self,
        raw_text: str,
        image_path: Optional[Union[str, Path]] = None,
        image: Optional[Image.Image] = None,
        image_hash: Optional[str] = None,
    ) -> None:
        """Registers a known image fixture and its exact ground-truth raw OCR text."""
        if image_path:
            norm_path = str(Path(image_path).resolve())
            self._path_registry[norm_path] = raw_text
            self._path_registry[Path(image_path).name] = raw_text

        if image:
            h = self.compute_image_hash(image)
            self._hash_registry[h] = raw_text

        if image_hash:
            self._hash_registry[image_hash] = raw_text

    def has_fixture(
        self,
        image: Image.Image,
        image_path: Optional[Union[str, Path]] = None,
    ) -> bool:
        """Returns True if the image is registered in the fixture registry."""
        if image_path:
            norm_path = str(Path(image_path).resolve())
            if norm_path in self._path_registry or Path(image_path).name in self._path_registry:
                return True
        h = self.compute_image_hash(image)
        return h in self._hash_registry

    def extract_text(
        self,
        image: Image.Image,
        image_path: Optional[Union[str, Path]] = None,
    ) -> Tuple[str, Optional[float], List[str], List[str]]:
        if image_path:
            norm_path = str(Path(image_path).resolve())
            if norm_path in self._path_registry:
                return self._path_registry[norm_path], None, [], []
            if Path(image_path).name in self._path_registry:
                return self._path_registry[Path(image_path).name], None, [], []

        h = self.compute_image_hash(image)
        if h in self._hash_registry:
            return self._hash_registry[h], None, [], []

        return "", None, ["Image not registered in fixture registry."], ["fixture_not_found"]


class AutoOCREngine(BaseOCREngine):
    """Coordinator that selects native Tesseract if present, or FixtureOCREngine for test fixtures."""

    def __init__(
        self,
        tesseract_engine: Optional[TesseractOCREngine] = None,
        fixture_engine: Optional[FixtureOCREngine] = None,
    ):
        """Initializes AutoOCREngine."""
        self.tesseract = tesseract_engine or TesseractOCREngine()
        self.fixture = fixture_engine or FixtureOCREngine()

    @property
    def engine_name(self) -> str:
        if self.tesseract.is_available():
            return "tesseract"
        return "fixture_engine"

    def is_available(self) -> bool:
        # Available if tesseract is operational or fixture engine is configured
        return self.tesseract.is_available() or self.fixture.is_available()

    def extract_text(
        self,
        image: Image.Image,
        image_path: Optional[Union[str, Path]] = None,
    ) -> Tuple[str, Optional[float], List[str], List[str]]:
        # 1. Prefer local Tesseract if available
        if self.tesseract.is_available():
            return self.tesseract.extract_text(image, image_path=image_path)

        # 2. Check fixture registry
        if self.fixture.has_fixture(image, image_path=image_path):
            return self.fixture.extract_text(image, image_path=image_path)

        # 3. Neither Tesseract is installed nor is this a registered fixture
        return (
            "",
            None,
            [
                "Local OCR engine (Tesseract) is not installed on this system, and "
                "the input image is not a registered test fixture."
            ],
            ["engine_unavailable"],
        )
