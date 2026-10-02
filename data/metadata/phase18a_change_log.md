# ScamShield AI — Phase 18A Change Log

## 1. Overview of Modifications

In accordance with the **Absolute Freeze Rule**, zero machine learning models were retrained, zero weights were modified, zero classification thresholds were tuned, and zero historical evaluation records were altered.

All modifications in Phase 18A were strictly architectural cleanups aimed at unifying entry points and improving deployment readiness.

---

## 2. Itemized Change Registry

### Change #1: Root `app.py` Entry Point Unification
- **File**: [`app.py`](file:///c:/Users/radika/OneDrive/Desktop/ScamShieldAI/app.py)
- **Classification**: Architectural Refactoring / Entry Point Unification.
- **Problem**: The root `app.py` file contained an early development prototype from Phase 1/2 that manually instantiated primitive rule scanners (`RuleDetector`, `RiskEngine`) and bypassed the entire modern `InvestigationService` (which includes Phases 3 through 17). Users running `streamlit run app.py` were presented with an obsolete prototype while the production console resided in `src/app/streamlit_app.py`.
- **Modification**: Refactored `app.py` to import and execute `src.app.streamlit_app.main()`.
- **Verification**:
  - `streamlit run app.py` launches the complete, modern production console.
  - `python -c "import app"` imports cleanly with zero side-effects.
  - All 432 unit and regression tests continue to pass with zero regressions.

### Change #2: Production Environment Template Creation
- **File**: [`.env.example`](file:///c:/Users/radika/OneDrive/Desktop/ScamShieldAI/.env.example)
- **Classification**: Configuration & Deployment Hardening.
- **Problem**: The repository lacked a standardized `.env.example` template, risking configuration drift and accidental secret commits.
- **Modification**: Created `.env.example` documenting all supported runtime flags (`SCAMSHIELD_OFFLINE_MODE`, `SCAMSHIELD_LOG_LEVEL`, `SCAMSHIELD_EXPLANATION_PROVIDER`, `TESSERACT_CMD`, feature flags) with safe, empty placeholders.
- **Verification**: Confirmed `.env` is ignored by `.gitignore`; no sensitive keys or credentials committed.

---

## 3. Invariance Verification
- **Model Binaries**: 0 changed (all 5 SHA-256 hashes matched bit-for-bit).
- **Thresholds**: 0 changed (0.30 baseline, 0.55 char n-gram, 0.50 hybrid/semantic).
- **Historical Reports**: 0 changed (Phases 1–17 frozen and preserved).
- **Test Invariance**: 432 / 432 passing (100.0%).
