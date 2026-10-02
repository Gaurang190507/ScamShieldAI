# Descriptive Reference Taxonomy of Indian Scam Modus Operandi 🇮🇳

> [!IMPORTANT]
> **CRITICAL ARCHITECTURAL PRINCIPLE**:
> This document is a **descriptive reference taxonomy**, NOT a rigid machine learning classification schema.
> Threat actors constantly mutate deceptive narratives, blend pretexts, and invent novel vectors.
> **ScamShield AI does not attempt to pigeonhole incoming text into fixed categorical silos.**
> Instead, the system analyzes fundamental **behavioral manipulation tactics** (e.g., urgency, coercion, authority claims, credential requests, payment redirection) which apply universally across known and emerging fraud types.

This catalog is **non-exhaustive** and serves as a domain reference grounded in advisories from the **Indian Cyber Crime Coordination Centre (I4C)**, **CERT-In**, and the **Reserve Bank of India (RBI)**.

---

## 1. Digital Payment & Banking Fraud

### 1.1 UPI-Related Fraud & Collect-Request Exploits
- **Modus Operandi**: Fraudsters exploit widespread confusion regarding Unified Payments Interface (UPI) mechanics. Victims are told they are "receiving a refund", "getting cashback", or "receiving payment for an OLX listing", but are sent a UPI collect request or asked to input their UPI PIN.
- **Core Principle Exploited**: Misunderstanding that *entering a UPI PIN is exclusively required for sending money, never for receiving it*.
- **Prevalent Tactics**: `impersonation`, `payment_request`, `reward_claim`, `refund_claim`.

### 1.2 QR-Code Scams (Scan-to-Receive Fallacy)
- **Modus Operandi**: The perpetrator sends a QR code via WhatsApp or email, claiming the victim must scan it to receive money or lottery winnings. Scanning the QR code triggers a debit authorization from the victim's account.
- **Prevalent Tactics**: `qr_code_request`, `payment_request`, `reward_claim`.

### 1.3 Refund / Accidental Reversal Claims
- **Modus Operandi**: The victim is contacted with claims that a merchant, utility board, or UPI user "accidentally overpaid" or that a cancelled transaction needs manual reversal through an external payment link.
- **Prevalent Tactics**: `refund_claim`, `urgency`, `payment_request`, `emotional_manipulation`.

---

## 2. Impersonation & Coercive Fraud

### 2.1 Fake Police / "Digital Arrest" & Legal Threats
- **Modus Operandi**: Victims receive high-pressure audio or video calls from individuals impersonating CBI officers, Mumbai Police, Narcotics Control Bureau (NCB), or the Supreme Court. The victim is falsely accused of sending illegal parcels (drugs, forged passports) or money laundering, told they are under "digital arrest", and coerced into transferring funds to "RBI verification accounts" to avoid immediate arrest.
- **Prevalent Tactics**: `impersonation`, `authority_claim`, `threat`, `fear_creation`, `secrecy_request`, `payment_request`.

### 2.2 Fake Government Communications (e-Challan, Electricity, PAN/KYC)
- **Modus Operandi**: Threat actors send SMS/WhatsApp alerts claiming:
  - Electricity connection will be disconnected tonight at 9:30 PM due to unpaid bill.
  - Pending traffic e-challan with an APK download link.
  - Bank account blocked due to unlinked PAN or incomplete KYC update.
- **Prevalent Tactics**: `authority_claim`, `urgency`, `account_suspension`, `threat`, `link_redirection`, `verification_request`.

### 2.3 Fake Customer Support & Search-Engine Poisoning
- **Modus Operandi**: Scammers publish fake toll-free numbers on Google Maps or search listings for airlines, banks, food delivery apps, or courier desks. When victims call to resolve a grievance, scammers demand remote access or payment of a nominal "registration fee".
- **Prevalent Tactics**: `impersonation`, `technical_support_claim`, `remote_access_request`, `payment_request`.

### 2.4 Fake Delivery / Courier Problem (India Post, FedEx, BlueDart)
- **Modus Operandi**: Messages claiming an incoming parcel cannot be delivered due to an incorrect address or missing ₹25 customs fee, leading to phishing sites that harvest debit card credentials and OTPs.
- **Prevalent Tactics**: `impersonation`, `delivery_problem`, `urgency`, `link_redirection`, `credential_request`.

---

## 3. Financial, Employment & Investment Scams

### 3.1 Task-Based & Part-Time Employment Scams (Telegram / WhatsApp)
- **Modus Operandi**: Victims are recruited via WhatsApp/Telegram with offers to earn ₹2,000–₹5,000 daily by "liking YouTube videos", "rating Google Maps locations", or "hotel reviews". After initial micro-payouts, victims are pressured to invest large sums into "prepaid merchant tasks".
- **Prevalent Tactics**: `job_offer`, `reward_claim`, `investment_pressure`, `emotional_manipulation`.

### 3.2 Fictitious Investment & Stock Trading Manipulation
- **Modus Operandi**: Fraudsters add victims to WhatsApp/Telegram groups claiming exclusive institutional IPO allotments, inside tips, or automated algorithmic trading bots offering guaranteed 30% weekly returns.
- **Prevalent Tactics**: `investment_pressure`, `authority_claim`, `reward_claim`, `secrecy_request`.

### 3.3 Instant Loan App Harassment
- **Modus Operandi**: Predatory apps offer collateral-free loans with immediate disbursal, requiring extensive device permissions (contacts, gallery, camera). Upon minor repayment delays, scammers extort victims using morphed photos sent to contact lists.
- **Prevalent Tactics**: `threat`, `fear_creation`, `personal_information_request`, `payment_request`.

### 3.4 Lottery & Reward Scams (KBC / Lucky Draw)
- **Modus Operandi**: Messages (often featuring Kaun Banega Crorepati branding) claiming the victim has won a ₹25 Lakh lottery, but must pay "processing fees" or "GST" to claim the prize.
- **Prevalent Tactics**: `impersonation`, `reward_claim`, `payment_request`, `urgency`.

---

## 4. Technical, Device & Identity Exploitation

### 4.1 Malicious Android Application (APK) Sideloading
- **Modus Operandi**: Victims are directed to install untrusted APKs disguised as official apps (e.g., `SBI_Reward.apk`, `PM_Kisan_Yojana.apk`, `e-Challan_Pay.apk`). Once installed, the malware forwards incoming SMS messages (intercepting OTPs) and grants remote access.
- **Prevalent Tactics**: `impersonation`, `link_redirection`, `verification_request`, `remote_access_request`.

### 4.2 Remote Access Application Coercion
- **Modus Operandi**: Posing as bank or technical support, fraudsters instruct victims to download AnyDesk, TeamViewer QuickSupport, or RustDesk to "assist" them, allowing the caller to view banking screens and capture passwords.
- **Prevalent Tactics**: `impersonation`, `technical_support_claim`, `remote_access_request`, `credential_request`.

### 4.3 SIM-Swap & eSIM QR Code Deception
- **Modus Operandi**: Telecom subscribers are persuaded to forward a SIM upgrade SMS or scan an eSIM QR code sent via email under the pretext of upgrading to 5G. This transfers the phone number to the scammer's physical device, breaking 2FA.
- **Prevalent Tactics**: `impersonation`, `urgency`, `verification_request`, `account_suspension`.

### 4.4 AI & Deepfake-Assisted Impersonation
- **Modus Operandi**: Synthetic voice cloning or video manipulation mimicking a family member, CEO, or friend requesting emergency financial help due to an accident or arrest.
- **Prevalent Tactics**: `impersonation`, `urgency`, `emotional_manipulation`, `payment_request`.

---

## 5. Emerging & Hybrid Attack Vectors
- **Aadhaar Enabled Payment System (AePS) Biometric Exploits**: Exploiting leaked biometric data for unauthorized micro-ATM cash withdrawals.
- **Social Media Honeytraps & Sextortion**: Video calls initiated by strangers on social platforms that are screen-recorded and used for immediate blackmail.
- **Crypto P2P Account Freezes**: Fraudulent funds routed through legitimate P2P crypto traders, causing cyber cells to freeze victim bank accounts.

---

## 6. How ScamShield AI Bridges Taxonomy to Tactics

| Real-World Scenario | Common Categorical Label | Underlying Behavioral Tactics Detected by ScamShield AI |
| :--- | :--- | :--- |
| Electricity bill cutoff notice | Fake Utility / e-Challan | `urgency`, `threat`, `account_suspension`, `phone_number`, `link_redirection` |
| Video call claiming CBI arrest | Digital Arrest Scam | `impersonation`, `authority_claim`, `threat`, `fear_creation`, `payment_request` |
| Part-time YouTube video liking | Telegram Job Scam | `job_offer`, `reward_claim`, `investment_pressure`, `payment_request` |
| Fake India Post address update | Delivery Phishing | `impersonation`, `delivery_problem`, `urgency`, `link_redirection`, `credential_request` |
| Legitimate bank low balance alert | *Non-Scam* | `payment_request` *(behavior present, but zero coercion/threat/phishing tactics)* |
