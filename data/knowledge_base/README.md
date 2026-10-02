# Knowledge Base Infrastructure 📚

## 1. Purpose & Strategic Separation
The `knowledge_base/` directory serves as the centralized repository for authoritative reference intelligence, fraud taxonomies, official regulatory advisories, and victim remediation guidance.

### Strict Architectural Boundaries:
ScamShield AI strictly enforces the separation of three distinct data layers:
1. **Training Data (`data/processed/`)**: Normalized textual messages with behavioral labels used for statistical and machine learning model training.
2. **Knowledge Base Sources (`data/knowledge_base/`)**: Structured reference guidance, official advisory summaries, and verified threat descriptions. **Government advisories and regulatory circulars are NEVER blindly dumped into training datasets.**
3. **Evaluation & Reference Sources (`data/evaluation/`)**: Isolated benchmarks (standard, hard negatives, novel patterns, adversarial) used exclusively to evaluate detection precision and generalization.

---

## 2. Directory Layout & Document Index

```text
data/knowledge_base/
├── README.md                          # Infrastructure guide, governance, and catalog
├── official/                          # Official government and regulatory reference guidance
│   ├── doc_i4c_citizen_guidelines.json    # I4C citizen guidelines, 1930 helpline, digital arrest
│   ├── doc_cert_in_mobile_threats.json    # CERT-In mobile trojans, malicious APKs, smishing
│   └── doc_rbi_financial_safety.json      # RBI BE(A)WARE financial fraud, UPI QR rules, lotteries
├── guidance/                          # Technical fraud analysis guidance
│   ├── doc_phishing_smishing_indicators.json # Phishing/smishing URL indicators & pressure tactics
│   ├── doc_credential_otp_theft.json         # OTP harvesting, vishing, remote access tools
│   └── doc_payment_qr_fraud.json             # QR code manipulation & reverse payment fraud
├── scam_patterns/                     # Specific modus operandi threat profiles
│   ├── doc_impersonation_authority.json      # Law enforcement/CBI impersonation, digital arrest
│   └── doc_fake_job_delivery_scams.json      # Part-time job task fraud, postal parcel scams
└── safety/                            # Victim mitigation and prevention playbooks
    ├── doc_victim_first_response.json        # Golden hour containment, account freeze, 1930
    └── doc_verification_best_practices.json  # Out-of-band verification, domain safety rules
```

---

## 3. Metadata Specification

Every knowledge base document adheres to a strict schema:
- `document_id`: Unique identifier (e.g., `doc_i4c_citizen_guidelines`).
- `title`: Formal title of advisory or reference standard.
- `source`: Issuing agency or research authority.
- `source_type`: Category (`official_knowledge`, `official_advisory`, `security_guidance`).
- `publication_date`: ISO date string (`YYYY-MM-DD`).
- `retrieval_date`: Date cataloged into ScamShield AI.
- `jurisdiction`: Applicable jurisdiction (`IN`, `Global`).
- `topic`: Canonical topic identifier.
- `license_status`: Provenance licensing status (`reference_advisory_excerpt`, `open_research_standard`).
- `content`: Factual reference guidance.

---

## 4. Governance & Acquisition Policy
- **Zero Bulk-Copying / Scraping**: Public availability does **NOT** equal unrestricted redistribution rights. Government portals, official advisory PDFs, and regulatory alerts are never mass-scraped or committed without verified licensing.
- **Traceable Excerpts & Summaries**: Authoritative facts are curated as structured, verified summaries with preserved source attribution.
- **Contextual Role**: Knowledge base assets are consumed exclusively by the RAG explanation layer (Phase 10) to ground human-readable explanations in trusted guidance. They are **never** used as training data for statistical classifiers.
