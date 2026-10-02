# Evaluation Subset: Hard Negatives 🛡️

## Purpose
The `hard_negatives` subset evaluates the system's ability to resist false alarms. It is dedicated to legitimate messages (`label = "non_scam"`) that contain characteristics superficially resembling scam behavior.

## Key Scenarios Included
- **Legitimate Security Alerts**: Actual bank OTP notifications, 2FA prompt messages, and password-reset confirmations.
- **Urgent Transactional Notices**: Valid electricity bill payment reminders, flight schedule changes, or medical appointment confirmations with countdown deadlines.
- **Official Delivery Alerts**: Genuine postal and courier status updates containing tracking links.
- **Customer Support Communications**: Legitimate support agents requesting non-credential verification info.

## Strategic Value
- Prevents the system from degenerating into a naive keyword detector (e.g., flagging any message containing "urgent", "OTP", or "verify" as a scam).
- Evaluates whether the risk engine accurately reports calibrated uncertainty or `Low risk` when malicious convergence is absent.
- No samples are fabricated at this stage.
