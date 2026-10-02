# ScamShield AI — Phase 18C OCR Deployment Strategy & Specification

**Document Version:** 1.0.0  
**Phase:** Phase 18C (Deployment & Release Readiness)  
**Date:** October 3, 2026  
**Status:** **OPERATIONAL SPECIFICATION — STRATEGY B WITH STRATEGY A ENABLEMENT**  

---

## 1. Context & Audited Host Reality

During Phase 9A, Phase 16, Phase 17, and Phase 18B audits, automated inspection via `OCREnvironmentDetector.inspect()` confirmed:
- `pytesseract` Python wrapper is installed/detectable.
- Native compiled `tesseract` binary and language training data (`eng.traineddata`, `hin.traineddata`) are **not present** on the default evaluation host PATH.

ScamShield AI **strictly avoids obfuscating this limitation**. Rather than pretending OCR is fully functional or allowing unhandled tracebacks to crash user sessions, ScamShield AI implements an honest, transparent, and resilient multi-tiered OCR deployment architecture.

---

## 2. Selected Release Strategy: Option B (Graceful Fallback & Environmental Transparency)

For standard cross-platform distribution and containerized deployments where external C++ OCR packages are omitted by default, ScamShield AI operates under **Strategy Option B**:

### Key Operational Characteristics of Strategy B:
1. **Dynamic Environment Probing**:
   Upon launching the Streamlit interface or invoking `InvestigationService`, `OCREnvironmentDetector.inspect()` inspects `shutil.which("tesseract")` and `os.environ.get("TESSERACT_CMD")`.
2. **Zero Crashing / Non-Blocking Pipeline**:
   If Tesseract is unavailable, image inputs are still accepted. The visual classifier extracts layout and pixel-level heuristics (Phase 9B), while the text and URL detection pipelines continue functioning with zero degradation.
3. **Transparent Infrastructure Notification**:
   In the `📸 Screenshot Scan` tab, an amber notice is displayed:
   > ℹ️ **OCR Infrastructure Notice**: Native Tesseract OCR is unconfigured or not installed on this host. ScamShield AI will safely use graceful visual fallback without crashing.
4. **No Exaggerated Claims**:
   The user interface explicitly notes `*No optical text was extracted from this image (engine unavailable or image contains no legible text)*` rather than claiming OCR analysis was performed.

---

## 3. Enablement Path: Upgrading to Option A (Full Native OCR)

For production deployments, enterprise security operations centers (SOCs), or container images requiring end-to-end OCR processing, administrators can upgrade to **Option A** with zero code modifications:

### 3.1 Windows Installation
```powershell
# Install official Tesseract OCR distribution via Windows Package Manager
winget install UB-Mannheim.TesseractOCR

# Configure .env or System Environment Variable
# Add to .env:
TESSERACT_CMD=C:\Program Files\Tesseract-OCR\tesseract.exe
```

### 3.2 Linux / Ubuntu / Debian Installation
```bash
sudo apt-get update && sudo apt-get install -y \
    tesseract-ocr \
    tesseract-ocr-eng \
    tesseract-ocr-hin \
    libtesseract-dev

# No environment variable needed if tesseract is in /usr/bin/tesseract
```

### 3.3 macOS Installation
```bash
brew install tesseract tesseract-lang
```

### 3.4 Verification
After installing, restart Streamlit or execute:
```bash
python -c "from src.ocr.environment import OCREnvironmentDetector; print(OCREnvironmentDetector.inspect())"
```
The console will display `🟢 Native OCR Available: Tesseract engine active` with full OCR text extraction enabled.
