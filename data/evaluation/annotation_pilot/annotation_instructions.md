# ScamShield AI: Annotation Pilot Protocol & Review Instructions 📝

## 1. Purpose of the Annotation Pilot
The annotation pilot tests ScamShield AI's annotation schema and guidelines on a diverse cohort of 60 real-world messages.
Its primary objective is **NOT** to maximize the percentage of detected scams, but to evaluate whether human annotators can reliably distinguish:
- **Scam vs. Non-Scam Intent** (separating fraudulent attacks from benign communications)
- **Behavioral Tactics vs. Superficial Keywords** (recognizing when urgency or payment language is legitimate vs. coercive)
- **Objective Evidence Grounding** (anchoring every tactic to verbatim substrings).

---

## 2. Step-by-Step Manual Review Workflow

```text
       [1] SOURCE RECORD
              ↓
       [2] RAW MESSAGE TEXT (Untrusted)
              ↓
       [3] PRIMARY ANNOTATOR (e.g. annotator_001)
              ↓
       [4] BINARY VERDICT: label ("scam" vs "non_scam")
              ↓
       [5] TACTICAL INDICATORS: tactics (Multi-label from controlled vocabulary)
              ↓
       [6] GROUNDED EVIDENCE: evidence_spans (Verbatim substrings from text)
              ↓
       [7] INTENDED ACTION: requested_action (click_link, send_money, reply, none, etc.)
              ↓
       [8] TARGET ASSET: target_asset (money, credentials, personal_info, none, etc.)
              ↓
       [9] TIME PRESSURE: urgency_level (none, low, medium, high, extreme)
              ↓
       [10] AUTHORITY CLAIM: impersonated_entity (bank, courier, police, none, etc.)
              ↓
       [11] UNCERTAINTY CALIBRATION: label_confidence ("high", "medium", "low")
              ↓
       [12] SECOND REVIEW / AUDIT (Arbitration on ambiguous/low-confidence cases)
              ↓
       [13] FINAL VALIDATED RECORD
```

---

## 3. Core Human Annotation Rules: Behavior Over Keywords

### Rule 1: A Payment Request Alone Does NOT Equal a Scam
- Legitimate billing notices, broadband invoices, utility bills, and cab receipts explicitly ask for payment or state charges.
- **Annotation**: `has_payment_request = True`, `label = "non_scam"`, `tactics = ["payment_request"]` (if payment solicited), `scam_category = "none"`.

### Rule 2: Expiry & Urgency in Security Alerts Are Often Legitimate
- An SMS stating *"Your OTP is valid for 10 minutes"* or *"Your flight leaves at 4 PM, arrive immediately"* expresses time limits.
- If the sender is not inducing panic to steal credentials or money, it is **non_scam**. Only mark `tactics = ["urgency"]` if time pressure is being used to force compliance.

### Rule 3: Commercial Spam vs. Fraudulent Scam
- A cold marketing SMS advertising ringtones, dating clubs, or horoscope horoscopes is **spam / unsolicited marketing**, but may not be an active fraudulent scam seeking to extract financial assets under false pretenses.
- If the offer is standard commercial spam without malicious deception or coercive exploitation, label `label = "non_scam"` (or `label = "scam"` with `label_confidence = "low"` and clear explanatory notes).

### Rule 4: Handling Ambiguity
- When an SMS contains too little context to verify legitimacy (e.g. *"Did you get my text?"* or *"Call me on 087012345"* without context):
  - Do **NOT** force a false certain verdict.
  - Set `label_confidence = "low"`.
  - Set `known_unknown_status = "unknown"`.
  - Record the uncertainty in `notes`.

### Rule 5: Pattern Grouping for Unknown Campaigns
- When annotating samples from external corpora where no verified threat campaign or template cluster exists, set `pattern_group_id = "unknown"`.
- Do **NOT** assign synthetic individual IDs like `grp_uci_unassigned_001` or `grp_uci_unassigned_002` during human annotation. An unknown campaign is not a known unique campaign.

---

## 4. Multi-Annotator Agreement Protocol (Future Phase Preparation)

To ensure scientific rigor when scaling annotation teams, the following agreement metrics will be evaluated across double-annotated samples:

1. **Binary Verdict Agreement (`label`)**: Measured via **Cohen’s Kappa ($\kappa$)**. Target: $\kappa \ge 0.80$.
2. **Multi-Label Tactic Agreement (`tactics`)**: Measured via **Macro Jaccard Similarity**:
   $$\text{Jaccard}(T_1, T_2) = \frac{|T_1 \cap T_2|}{|T_1 \cup T_2|}$$
   Target: Average Jaccard $\ge 0.70$.
3. **Evidence Span Agreement (`evidence_spans`)**: Measured via character-level span overlap Intersection-over-Union (IoU) on matched tactics.
4. **Disagreement Resolution**: Any sample where annotators disagree on `label` or disagree on $\ge 2$ tactics is escalated to a Senior Security Reviewer for binding arbitration.
