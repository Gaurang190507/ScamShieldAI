# ScamShield AI — Phase 17 Regression Test Report

## 1. Test Suite Summary & Execution Results

All regression testing for Phase 17 was conducted against the unified test suite comprising 399 historical Phase 1–15 tests (including the 40-test Phase 15 security suite), 6 historical Phase 16 validation tests, and 27 newly created Phase 17 repair regression tests.

- **Phase 1–15 Historical Tests**: 399 / 399 PASS
- **Phase 15 Authoritative Security Suite**: 40 / 40 PASS
- **Phase 16 Historical Tests**: 6 / 6 PASS
- **Phase 17 New Repair Tests**: 27 / 27 PASS
- **Total Tests Executed**: **432 / 432 PASS** (100.0%)
- **Failures / Errors**: 0
- **Historical Regressions**: 0
- **Execution Duration**: 31.033s
- **Python Environment**: Python 3.13.6 (Windows 11)

---

## 2. Phase 17 Test Category Verification (Categories A – T)

The 27 Phase 17 regression tests in `tests/test_phase17_repair.py` validate all 20 required failure remediation categories (A through T):

| Category | Description | Test Function | Result |
|---|---|---|---|
| **A** | Character-spaced text (`U R G E N T`) | `test_category_a_character_spaced_text` | PASS |
| **B** | Punctuation-separated text (`U.R.G.E.N.T`) | `test_category_b_punctuation_separated_text` | PASS |
| **C** | Cyrillic homoglyph text (`раураl` with Cyrillic а/р) | `test_category_c_cyrillic_homoglyphs` | PASS |
| **D** | Defanged URLs (`hxxp[:]//scam[.]com`) | `test_category_d_defanged_urls` | PASS |
| **E** | Clean legitimate text preservation (`hello world`) | `test_category_e_clean_text_preservation` | PASS |
| **F** | Clean legitimate multi-word sentences | `test_category_f_clean_multi_word_sentence` | PASS |
| **G** | Valid single-letter English words (`a big apple`) | `test_category_g_valid_single_letters_preserved` | PASS |
| **H** | Clean institutional domain (`https://www.onlinesbi.sbi/`) | `test_category_h_clean_institutional_url_sbi` | PASS |
| **I** | Clean government domain (`https://www.incometax.gov.in/`) | `test_category_i_clean_government_url_incometax` | PASS |
| **J** | Suspicious IP-based URL (`http://192.168.1.1/login`) | `test_category_j_suspicious_ip_url` | PASS |
| **K** | Suspicious deep-subdomain URL (`http://login.verify.account.update.bank.com.xyz/`) | `test_category_k_suspicious_subdomain_url` | PASS |
| **L** | Legitimate delivery handover with brand & OTP (doorstep) | `test_category_l_legitimate_delivery_handover_otp` | PASS |
| **M** | Coercive delivery notification with fee / phishing link | `test_category_m_coercive_delivery_scam` | PASS |
| **N** | Legitimate bank service notification | `test_category_n_legitimate_bank_notification` | PASS |
| **O** | Impersonated bank notification with urgent credential link | `test_category_o_impersonated_bank_phishing` | PASS |
| **P** | Coercive authority / digital arrest narrative | `test_category_p_coercive_authority_digital_arrest` | PASS |
| **Q** | Conversational urgency narrative | `test_category_q_conversational_urgency` | PASS |
| **R** | Indirect payment demand narrative | `test_category_r_indirect_payment_demand` | PASS |
| **S** | Native OCR available handling | `test_category_s_ocr_environment_detection` | PASS |
| **T** | Native OCR missing / unconfigured host handling | `test_category_t_ocr_missing_graceful_handling` | PASS |

---

## 3. Historical Suite Regression Invariance

All 405 historical tests prior to Phase 17 were re-verified without any modifications:

| Test Scope | Modules Included | Test Count | Status |
|---|---|---|---|
| **Phase 1–14 Functional Tests** | Text classifier, char n-gram, tactic rules, semantic analysis, investigation service, API, RAG, multimodal, dataset validators, preprocessing | 359 | PASS |
| **Phase 15 Security Suite** | `test_phase15_security.py` (Path security, URL security, image security, prompt injection, secret redaction, gatekeeper, zero-network) | 40 | PASS |
| **Phase 16 Historical Tests** | `test_phase16_validation.py` | 6 | PASS |
| **Phase 17 Repair Tests** | `test_phase17_repair.py` (Categories A–T) | 27 | PASS |
| **Total** | | **432** | **ALL PASS** |

---

## 4. Frozen Release Artifact Cryptographic Integrity

Each of the 5 canonical release artifacts was subjected to SHA-256 hashing during the Phase 17 regression test run:

| Artifact Key | File Path | Authoritative SHA-256 Digest | Verified Measured Digest | Integrity Status |
|---|---|---|---|---|
| `baseline_vectorizer` | `models/baseline/tfidf_vectorizer.joblib` | `a3c25ebaa90d0df69e80101cd8f6ac9e6b4c17c579a476da26a722881c60e1d5` | `a3c25ebaa90d0df69e80101cd8f6ac9e6b4c17c579a476da26a722881c60e1d5` | MATCH / UNCHANGED |
| `baseline_classifier` | `models/baseline/logistic_regression.joblib` | `93fd14c652241e46583de4beb3f62546d78932b629d0b8e930808c2a4f8336e6` | `93fd14c652241e46583de4beb3f62546d78932b629d0b8e930808c2a4f8336e6` | MATCH / UNCHANGED |
| `char_vectorizer` | `models/phase13/char_ngram/char_vectorizer.joblib` | `bd53f31398d015130a711c7657cf31fe13e952e749631b3147b89532b1b3f142` | `bd53f31398d015130a711c7657cf31fe13e952e749631b3147b89532b1b3f142` | MATCH / UNCHANGED |
| `char_classifier` | `models/phase13/char_ngram/char_classifier.joblib` | `86021d25325eb27a989651a7da23f0c3c8a6f78df660bf64694d107a3ff281a3` | `86021d25325eb27a989651a7da23f0c3c8a6f78df660bf64694d107a3ff281a3` | MATCH / UNCHANGED |
| `reference_embeddings` | `data/semantic/reference/reference_embeddings.npy` | `f4ad641ae6d3a34502a7f71ceaca1322762d9852c348c4e36cb767da2790101b` | `f4ad641ae6d3a34502a7f71ceaca1322762d9852c348c4e36cb767da2790101b` | MATCH / UNCHANGED |
