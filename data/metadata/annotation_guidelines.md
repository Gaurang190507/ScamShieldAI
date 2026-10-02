# ScamShield AI: Annotation Guidelines ✍️

These guidelines establish standardized, reproducible annotation protocols for human reviewers and domain analysts annotating communication content for ScamShield AI.

---

## 1. Core Annotation Philosophy

1. **Tactics First, Categories Second**: Focus on *how* the sender manipulates the recipient rather than fitting the message into a rigid scam category.
2. **Behavioral Objectivity**: Base tactic assignments solely on explicit language, behavioral indicators, and structural cues present in the text.
3. **No Automatic Guilt**: Legitimate business communications often contain payment requests, countdown deadlines, and security reminders. Do **not** mark a message as `scam` solely because it contains an urgent request or a payment link.
4. **Grounded Evidence Spans**: Every tactic assigned to a sample must be anchored to an exact textual span in `evidence_spans`.

---

## 2. Multi-Label Annotation Protocol

A single message routinely combines multiple manipulative levers. Annotators must assign **all** tactics that apply.

### Typical Combination Patterns
- **Authority Impersonation + Fear/Threat + Account Suspension**:
  > *"State Police Cyber Cell: Your identity is linked to illegal narcotics. Your assets will be frozen unless verified."*
- **Urgency + Delivery Problem + Link Redirection**:
  > *"Package delivery delayed due to unpaid customs fee of $2.10. Update address immediately at: [link]"*

---

## 3. Controlled Vocabulary of Tactics: Definitions & Rules

### 1. `impersonation`
- **Definition**: The sender purports or implies to represent an entity, brand, government body, executive, colleague, or friend.
- **Assign when**: The text invokes the name, logo, title, or authority of a recognized organization or acquaintance.
- **Do NOT assign when**: The message is a genuine, verified communication from the actual organization, or where no entity identity is claimed.
- **Positive Example**: *"This is Officer Davis from the IRS Internal Audit Unit."*
- **Negative Example**: *"Hey, please call me back when you're free."*

### 2. `urgency`
- **Definition**: Artificial time pressure intended to induce impulsive action and bypass critical reflection.
- **Assign when**: Phrasing contains countdown deadlines, "immediate action", or expiration warnings.
- **Positive Example**: *"Respond within 15 minutes or your session will permanently terminate."*
- **Negative Example**: *"Our offices are open Monday through Friday, 9am to 5pm."*

### 3. `threat`
- **Definition**: Explicit declarations of adverse harm, financial loss, legal consequences, or physical/social retaliation if compliance is withheld.
- **Positive Example**: *"A warrant for your arrest has been submitted to the local sheriff's office."*
- **Negative Example**: *"Late payments may incur a standard $5 billing fee pursuant to your utility terms."*

### 4. `fear_creation`
- **Definition**: Eliciting panic, distress, or vulnerability without necessarily stating a formal legal threat (e.g., claiming intimate footage was captured or family member is hospitalized).
- **Positive Example**: *"We recorded you through your webcam while visiting sensitive websites."*
- **Negative Example**: *"Remember to turn on multi-factor authentication to protect your passwords."*

### 5. `authority_claim`
- **Definition**: Explicitly invoking state laws, statutory compliance, regulatory mandates, or judicial orders to demand obedience.
- **Positive Example**: *"Under Section 144B of the National Security Code, you are mandated to comply."*
- **Negative Example**: *"Per our company's refund policy, please keep your receipt."*

### 6. `payment_request`
- **Definition**: Soliciting money, remittances, gift cards, or cryptocurrency transfers.
- **IMPORTANT**: `payment_request` alone does **NOT** imply that a message is a scam.
- **Positive Example (Scam context)**: *"Send 0.05 BTC to the wallet address below to unlock your file access."*
- **Positive Example (Legitimate context)**: *"Your monthly broadband bill of $49.99 is due on Oct 10."*
- **Negative Example**: *"Please download the latest product brochure."*

### 7. `credential_request`
- **Definition**: Asking the user to disclose passwords, secret PINs, recovery phrases, or cryptographic keys.
- **Positive Example**: *"Please enter your email password to authenticate your mailbox quota upgrade."*
- **Negative Example**: *"You can reset your password anytime from your profile settings page."*

### 8. `otp_request`
- **Definition**: Explicitly asking the recipient to read back, forward, or input a One-Time Password (OTP) or 2FA token.
- **Positive Example**: *"Share the 6-digit verification code sent to your SMS so the agent can restore your line."*
- **Negative Example**: *"Your verification code is 492019. Do NOT share this code with anyone."*

### 9. `personal_information_request`
- **Definition**: Soliciting personally identifiable information (PII) such as Social Security Numbers, National IDs, date of birth, mother's maiden name, or home address.
- **Positive Example**: *"Provide your full SSN, mother's maiden name, and date of birth to claim the tax rebate."*
- **Negative Example**: *"Hi Alex, please let me know your preferred mailing address for the wedding invite."*

### 10. `account_suspension`
- **Definition**: Warning or claiming that the user's account, subscription, bank card, or access privileges are locked, terminated, or pending immediate closure.
- **Positive Example**: *"Notice: Your Netflix subscription has been terminated due to billing failure."*
- **Negative Example**: *"You have successfully signed out from your Chrome browser session."*

### 11. `verification_request`
- **Definition**: Demanding that the user perform an identity re-check, KYC update, device authorization, or profile confirmation.
- **Positive Example**: *"Mandatory: Update your bank KYC documents today to prevent disruption."*
- **Negative Example**: *"Your profile has been verified. Thank you for signing up."*

### 12. `reward_claim`
- **Definition**: Promising an unearned prize, lottery winning, unexpected windfall, gift card, or cashback.
- **Positive Example**: *"Congratulations! You have been selected as the $5,000 Walmart Shopper of the Day."*
- **Negative Example**: *"You earned 50 loyalty points on your purchase of groceries today."*

### 13. `investment_pressure`
- **Definition**: Promoting guaranteed high returns, zero-risk trading, algorithmic crypto bots, or exclusive pre-IPO stakes.
- **Positive Example**: *"Earn 20% daily compounding returns with our AI crypto arbitrage engine. Guaranteed."*
- **Negative Example**: *"Past performance is not indicative of future market returns. Read fund prospectus."*

### 14. `job_offer`
- **Definition**: Offering high-paying remote employment, data entry, task-based assignments, or secret shopper roles with minimal qualifications.
- **Positive Example**: *"Work from home 1 hour a day and earn $400 daily liking YouTube videos."*
- **Negative Example**: *"Thank you for applying to Google for the Software Engineer position. Here is our interview schedule."*

### 15. `emotional_manipulation`
- **Definition**: Exploiting compassion, pity, guilt, loneliness, or moral obligation.
- **Positive Example**: *"I am stranded at the border with no medication and nobody else to help me."*
- **Negative Example**: *"We appreciate your support during our annual charity fundraiser."*

### 16. `secrecy_request`
- **Definition**: Instructing the victim not to discuss the transaction, message, or call with family, branch managers, or colleagues.
- **Positive Example**: *"Do not mention this transaction to bank tellers as this is an internal covert audit."*
- **Negative Example**: *"Confidential: This email contains privileged client legal materials."*

### 17. `romance_manipulation`
- **Definition**: Feigning rapid affection, love, or intimacy to establish trust before introducing financial demands.
- **Positive Example**: *"My dearest love, I cannot wait to marry you once I resolve this overseas customs bond."*
- **Negative Example**: *"Happy anniversary sweetheart, see you at dinner tonight!"*

### 18. `technical_support_claim`
- **Definition**: Claiming a virus, Trojan, Windows crash, or security breach has been identified on the recipient's machine.
- **Positive Example**: *"Alert: Windows Defender detected Trojan.Spyware32 on your computer. Call Microsoft Support now."*
- **Negative Example**: *"Your laptop repair ticket #8102 is complete and ready for pickup at our service desk."*

### 19. `refund_claim`
- **Definition**: Notifying the recipient of an accidental overpayment, subscription renewal error, or eligible refund that requires their intervention to reverse.
- **Positive Example**: *"You were accidentally billed $499 for Geek Squad. Call now to claim your immediate refund."*
- **Negative Example**: *"Your refund of $14.20 for the returned book has been credited to your Visa card ending in 1029."*

### 20. `delivery_problem`
- **Definition**: Claiming a package cannot be delivered due to an incomplete address, missing tax payment, or failed gate access.
- **Positive Example**: *"USPS: Parcel tracking #9201948 held at depot due to incomplete street number. Click link to confirm."*
- **Negative Example**: *"Your parcel has been delivered to your front porch. Proof of delivery: [link]"*

### 21. `qr_code_request`
- **Definition**: Instructing the recipient to scan a Quick Response (QR) code, especially under the pretext of receiving money, authentication, or accessing a menu/form.
- **Positive Example**: *"Scan this QR code in your banking app to receive payment of $150 from the buyer."*
- **Negative Example**: *"Scan the QR code at your table to view our dinner specials."*

### 22. `remote_access_request`
- **Definition**: Demanding that the user install remote administration tools such as AnyDesk, TeamViewer, QuickAssist, or UltraViewer.
- **Positive Example**: *"Download AnyDesk so our security technician can remotely purge the Trojan from your PC."*
- **Negative Example**: *"Please accept the IT Helpdesk screen-share invitation during our scheduled 10:00 AM meeting."*

### 23. `link_redirection`
- **Definition**: Pushing the recipient to click an external link, often masked via shortened URLs, misspellings, or ambiguous anchor text.
- **Positive Example**: *"Click here to resolve your case: http://bit.ly/3x8Ab92"*
- **Negative Example**: *"You can view the full whitepaper at https://www.mit.edu/research/paper.pdf"*

---

## 4. Evidence Span Annotation Guidelines

1. **Exact Substring Match**: The `evidence` field in `evidence_spans` must match a verbatim substring from `text`.
2. **Minimal Sufficient Span**: Do not select the entire message. Extract the exact phrase that triggered the tactic assignment.
3. **Multi-Span Support**: If multiple distinct phrases support the same tactic, annotate both or choose the most direct indicator.

---

## 5. Handling Legitimate Messages with Suspicious Features (Hard Negatives)

Many genuine transactional alerts employ urgent wording or links:
- **Rule**: If a message contains urgency, assign `tactics = ["urgency"]` even if `label = "non_scam"`.
- **Reason**: Tactics reflect linguistic behavior; the `label` reflects fraudulent intent. Disentangling tactics from labels is what allows ScamShield AI to learn true multi-signal convergence rather than simple keyword matching.

---

## 6. Uncertainty & Confidence Scoring

- **`high`**: Overwhelming indicators, clear official advisory sample, or verified legitimate transactional notice.
- **`medium`**: Probable scam or benign message, but phrasing is terse or ambiguous.
- **`low`**: Highly truncated text, conversational snippet missing context, or conflicting behavioral signals.

---

## 7. External Dataset Ingestion & The "Spam vs. Scam" Protocol

When ingesting legacy or external datasets (e.g. UCI SMS Spam Collection):
1. **Normalization Assumption**: External binary labels like `spam` are ingested as `scam`, and `ham` as `non_scam`.
2. **Semantic Boundary**: Not all spam messages are scams. Commercial cold outreach, unwanted product offers, and marketing texts are technically spam but lack malicious intent to defraud. Conversely, scams employ active social engineering, intimidation, credential theft, or extortion.
3. **No Automatic Synthetic Annotations**: External samples must **never** be backfilled with synthetic or assumed tactic tags during automated ingestion. Their `tactics` and `evidence_spans` fields must remain empty (`[]`) until an authorized human annotator or domain reviewer validates the evidence spans.
4. **Complementary Data Requirement**: Because legacy spam datasets cannot serve as the sole ground truth, ScamShield AI requires dedicated scam advisories and high-fidelity threat samples to establish true behavioral scam detection.

---

## 8. Language Scope & Regional Strategy

- **Initial Active Scope**: English (`en`). Phase 1C focuses strictly on verified English SMS benchmarks.
- **Future Multilingual Scope**: Code-switched Hinglish (`hi-en`) and regional Indian languages.
- **Ingestion Policy**: Any future Hinglish dataset must undergo its own independent provenance check, license review, and annotation calibration before being admitted into the repository.

---

## 9. Manual Review Workflow

To transition from automated raw ingestion to verified gold-standard ground truth, human annotators follow this strict 13-stage workflow:

1. **Source Record Inspection**: Verify source provenance (`source_reference`).
2. **Raw Text Isolation**: Read raw message without executing code or resolving URLs.
3. **Primary Annotator Assignment**: Assign unique anonymized identifier (e.g. `annotator_001`).
4. **Binary Ground-Truth Determination**: Assign `label` (`scam` vs. `non_scam`).
5. **Tactical Multi-Label Assignment**: Select all matching tactics from the 23 controlled vocabulary items.
6. **Verbatim Evidence Anchoring**: Extract exact substrings from `text` into `evidence_spans` for each assigned tactic.
7. **Action Classification**: Identify primary requested victim action (`requested_action`).
8. **Asset Identification**: Identify target financial or personal asset (`target_asset`).
9. **Urgency Assessment**: Rate psychological time pressure (`urgency_level`).
10. **Impersonated Entity**: Identify claimed authority or corporate entity (`impersonated_entity`).
11. **Confidence & Ambiguity Calibration**: Record `label_confidence` (`high`, `medium`, `low`) and `known_unknown_status`.
12. **Second Review / Audit**: Independent cross-check on ambiguous or high-discrepancy items.
13. **Final Schema Validation**: Automated execution of `DatasetValidator` to guarantee structural compliance.

---

## 10. Behavioral Annotation Rules & Ambiguity Protocol

- **Behavior over Keywords**: Urgency language, payment requests, or links in legitimate transactional notices do NOT make a message a scam.
- **Handling Incomplete Context**: If a snippet lacks sufficient context to prove fraudulent or benign intent (e.g., *"Got meh... When?"* or *"Call 087012345"*), annotators must set `label_confidence = "low"`, `known_unknown_status = "unknown"`, and explain the uncertainty in `notes`.
- **Unknown Pattern Groups**: When annotating individual samples where no campaign or template group is verified, annotators must set `pattern_group_id = "unknown"`. Annotators must never create artificial unique group IDs.

---

## 11. Multi-Annotator Agreement Protocol

For scaled dataset expansion, double-annotation agreement is evaluated using:
1. **Cohen's Kappa ($\kappa$)**: Evaluates inter-annotator agreement on binary `label`. Requires $\kappa \ge 0.80$.
2. **Macro Jaccard Similarity**: Evaluates agreement on multi-label `tactics`. Requires average Jaccard $\ge 0.70$.
3. **Span Overlap Intersection-over-Union (IoU)**: Evaluates agreement on textual `evidence_spans`.
4. **Arbitration**: Disagreements on `label` are arbitrated by a lead investigator.


