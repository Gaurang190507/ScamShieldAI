# ScamShield AI — Phase 18C Live Demonstration Script

**Target Duration:** 5 to 7 Minutes  
**Audience:** Security Analysts, Incident Responders, Product Evaluators, General Users  
**Prerequisites:** Streamlit application running (`streamlit run app.py`).

---

## Demonstration Overview

| Stage | Action / Workflow | Key Visual or Forensic Feature to Highlight | Estimated Time |
| :---: | :--- | :--- | :---: |
| **1** | **Introduction & Orientation** | Brand identity, "Offline-First", Zero External Network Calls | 0:30 |
| **2** | **Quick Scan (Consumer Mode)** | Preset chips, immediate verdict card, actionable guidance | 1:00 |
| **3** | **Deep Investigation (Forensics)** | 11-step analysis, tactic quotes, verbatim evidence spans | 1:30 |
| **4** | **Passive URL & Semantic Memory** | Non-contact structural inspection, "Known" vs "Emerging" | 1:00 |
| **5** | **RAG & Non-Authoritative AI** | Official RBI/TRAI citations, fail-closed grounding badge | 0:45 |
| **6** | **Legitimate False-Positive Test** | Benign salary alert & Amazon delivery handover | 0:45 |
| **7** | **URL-Only & Screenshot Scan** | Modality routing, OCR environment notice, Case History | 1:00 |

---

## Step-by-Step Walkthrough Flow

### 1. Launch & Orientation (0:00 – 0:30)
1. Navigate to `http://localhost:8501`.
2. Point out the top header:  
   *"ScamShield AI — AI-Powered Scam Investigation & Risk Analysis"*.
3. Highlight the sidebar:  
   - Offline Mode: `🟢 Offline Mode Active (Zero external network calls)`
   - Model Provenance: `ScamShield v1.0.0` with frozen deterministic baseline.

### 2. Quick Scan: Banking Phishing Lure (0:30 – 1:30)
1. Select the **`⚡ Quick Scan`** tab.
2. Click the preset scenario chip: **`🏦 Bank KYC Suspended`**.
3. The input box populates with:  
   `"URGENT: Your SBI bank account will be blocked today due to pending KYC..."`
4. Click **`⚡ Run Quick Scan`**.
5. **Show Result**:
   - Prominent red verdict card: `🚨 VERDICT: LIKELY SCAM`.
   - Key Risk Signals: Urgency, Credential Harvesting, Financial Coercion.
   - Recommended Actions: Dial 1930, report to cybercrime.gov.in, do not click link.
6. Click **`🔬 Open Full Investigation Breakdown`** to transition seamlessly to Deep Investigation.

### 3. Deep Investigation: Forensic Dissection (1:30 – 3:00)
1. On the **`🔬 Deep Investigation`** tab, observe the full 11-layer evidence stack:
   - **Assessment Card**: Status `likely_scam`, Evidence Level `HIGH`, Signal Consistency `Convergent`.
   - **Manipulative Tactics**: Expand tactic cards (`urgency`, `account_suspension`, `impersonation`) showing grounded text quotes.
   - **Verbatim Evidence Spans**: Highlight character-exact spans extracted from the raw message.

### 4. Passive URL Analysis & Semantic Memory (3:00 – 4:00)
1. Scroll to **Passive URL Analysis**:
   - Emphasize the security banner:  
     `🛡️ PASSIVE ANALYSIS ONLY — Zero external HTTP connections made.`
   - Point to structural indicators: suspicious TLD (`.xyz`), brand mismatch (`sbi` in subdomain vs unrelated registrar).
2. Scroll to **Semantic Memory & Novelty**:
   - Show similarity distance against 3,881 frozen reference vectors.
   - Note the status: `"Known Pattern"` (aligned with historical banking phishing campaigns).

### 5. Regulatory RAG & Grounded AI Explanation (4:00 – 4:45)
1. Scroll to **Verified Regulatory Guidance (RAG)**:
   - Show verified RBI and CERT-In advisory citations isolated from generative text.
2. Scroll to **Plain-Language AI Explanation**:
   - Highlight the green badge: `Verified Evidence-Grounded`.
   - Note that AI explanations are strictly subordinate to deterministic classifiers.

### 6. Disambiguation: Legitimate Message Testing (4:45 – 5:30)
1. Return to the input box and paste:  
   `"Your Amazon delivery agent is out for delivery. Share delivery code 491024 with the driver at the door to receive your package."`
2. Click **`🔬 Investigate Content`**.
3. **Show Result**:
   - Status evaluates to `likely_non_scam`.
   - Decision rule: `rule_p17_delivery_brand_disambiguation`.
   - Explains that the brand reference is a benign physical doorstep delivery code, preventing false positives.

### 7. Multi-Modal Modes & Case History (5:30 – 6:30)
1. Select **`📸 Screenshot Scan`**:
   - Show the image upload area.
   - Highlight the **Infrastructure Notice**: explains that native Tesseract is unconfigured on the test host, showing exact install commands while keeping the visual pipeline fully operational without crashing.
2. Select **`📜 Case History`**:
   - Show the session table containing all investigated cases (Timestamps, Modalities, Verdicts, Latencies).
   - Emphasize privacy: records are stored strictly in ephemeral RAM with zero disk writes.
3. Conclude by demonstrating the one-click **`📥 Download JSON Report`** and **`📥 Download Markdown Summary`**.
