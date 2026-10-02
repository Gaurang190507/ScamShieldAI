# ScamShield AI — Phase 18C Environment & Platform Specifications

**Document Version:** 1.0.0  
**Phase:** Phase 18C (Deployment & Release Readiness)  
**Date:** October 3, 2026  

---

## 1. Environment Compatibility Matrix

The following specification details the exact runtime environment requirements tested and verified for ScamShield AI:

| Requirement | Supported Value / Range | Validated Value in Test Environment |
| :--- | :--- | :--- |
| **Python** | `>= 3.10, <= 3.13.x` | `3.13.6` (64-bit) |
| **Operating System** | Windows 10/11, Ubuntu 20.04/22.04 LTS, macOS 12+ (Intel & Apple Silicon) | Windows 11 Enterprise (Build 26100) |
| **RAM** | `4 GB` minimum, `8 GB` recommended | 16 GB Available |
| **CPU** | 2 cores minimum, 4 cores recommended (x86_64 or ARM64) | Intel / AMD 64-bit multi-core |
| **Storage** | `~2.5 GB` (code + models + PyTorch CPU runtime + MiniLM cache) | SSD NVMe |
| **Streamlit** | `>= 1.28.0` | `1.39.0` |

---

## 2. Hardware Resource Budget

### Memory (RAM) Allocation
- **Python Runtime & Core Libraries** (numpy, pandas, scikit-learn): ~120 MB
- **Sentence-Transformers & PyTorch** (`all-MiniLM-L6-v2` CPU weights): ~220 MB
- **Reference Semantic Corpus** (3,881 float32 embedding vectors): ~6 MB
- **TF-IDF & Character N-Gram Vocabulary Matrices**: ~25 MB
- **Streamlit In-Memory Session State**: ~20 MB
- **Peak RSS Footprint Under Load**: **~450–650 MB**

### Storage Allocation
- **Repository Source Code & Documentation**: ~15 MB
- **Model Artifacts (`models/` + reference embeddings)**: ~6.6 MB
- **Preprocessed Frozen Training / Benchmark Sets**: ~15 MB
- **Python Virtual Environment (`.venv`)**: ~1.8–2.2 GB (primarily PyTorch CPU wheels)

---

## 3. Platform Dependencies & Optional Software

1. **Optical Character Recognition (OCR)**:
   - *Status*: Optional external system dependency.
   - *Engine*: Google Tesseract OCR (v4.0 or v5.0+).
   - *Windows Package*: `winget install UB-Mannheim.TesseractOCR`
   - *Linux Package*: `sudo apt install tesseract-ocr tesseract-ocr-eng tesseract-ocr-hin`
   - *Fallback Behavior*: Graceful visual fallback with clear UI notice when absent.

2. **Network Egress (Optional GenAI)**:
   - *Status*: Disabled by default (`SCAMSHIELD_OFFLINE_MODE=true`).
   - *Supported Optional Cloud Providers*: Groq (`groq`), Google Gemini (`gemini`).
   - *Offline Guarantee*: In default mode (`mock`), zero sockets are opened and zero DNS lookups occur.
