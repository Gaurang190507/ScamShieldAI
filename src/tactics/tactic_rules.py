"""Declarative tactic rule definitions for ScamShield AI.

Implements structured, context-aware regex patterns for all 23 canonical
scam tactics defined in the ScamShield AI taxonomy.

Rules are strictly:
- Deterministic
- Offline
- Explainable with human-readable rationales
- Equipped with negative contextual guards to avoid naive false positives.
"""

from dataclasses import dataclass
import re
from typing import List, Optional, Pattern


@dataclass
class TacticRule:
    """Structured rule definition for a single behavioral tactic indicator."""

    rule_id: str
    tactic: str
    pattern: Pattern[str]
    severity: str  # "low", "medium", "high"
    evidence_strength: str  # "low", "medium", "high"
    reason: str
    negative_pattern: Optional[Pattern[str]] = None


# Canonical Severity Mapping according to Phase 6 Framework
TACTIC_SEVERITY: dict[str, str] = {
    # High Severity: Direct exploitation / catastrophic compromise
    "remote_access_request": "high",
    "otp_request": "high",
    "credential_request": "high",
    "payment_request": "high",
    "secrecy_request": "high",
    "account_suspension": "high",
    # Medium Severity: High-pressure manipulation / pretexts
    "urgency": "medium",
    "threat": "medium",
    "impersonation": "medium",
    "fear_creation": "medium",
    "authority_claim": "medium",
    "verification_request": "medium",
    "link_redirection": "medium",
    "qr_code_request": "medium",
    "technical_support_claim": "medium",
    "personal_information_request": "medium",
    "investment_pressure": "medium",
    "emotional_manipulation": "medium",
    "romance_manipulation": "medium",
    # Low Severity: Initial bait / lures
    "reward_claim": "low",
    "job_offer": "low",
    "delivery_problem": "low",
    "refund_claim": "low",
}


def build_tactic_rules() -> List[TacticRule]:
    """Builds and returns the comprehensive catalog of compiled tactic rules."""
    rules: List[TacticRule] = [
        # =========================================================================
        # 1. IMPERSONATION (severity: medium)
        # =========================================================================
        TacticRule(
            rule_id="imp_bank_001",
            tactic="impersonation",
            pattern=re.compile(
                r"\b(?:SBI|State\s+Bank(?:\s+of\s+India)?|HDFC(?:\s+Bank)?|ICICI(?:\s+Bank)?|"
                r"Axis\s+Bank|Punjab\s+National\s+Bank|PNB|Reserve\s+Bank\s+of\s+India|RBI|"
                r"PayPal|Chase(?:\s+Bank)?|Wells\s+Fargo|Bank\s+of\s+America|Barclays|"
                r"NatWest|HSBC|Kotak(?:\s+Mahindra)?|IndusInd|Canara\s+Bank)\b",
                re.IGNORECASE,
            ),
            severity="medium",
            evidence_strength="medium",
            reason="Claims representation of a prominent banking or financial institution.",
        ),
        TacticRule(
            rule_id="imp_telecom_002",
            tactic="impersonation",
            pattern=re.compile(
                r"\b(?:Jio|Airtel|Vodafone(?:\s+Idea)?|Vi|BSNL|MTNL|Verizon|AT&T|T-Mobile|"
                r"Orange|EE|O2)\b",
                re.IGNORECASE,
            ),
            severity="medium",
            evidence_strength="medium",
            reason="Claims representation of a major telecommunications operator.",
        ),
        TacticRule(
            rule_id="imp_gov_003",
            tactic="impersonation",
            pattern=re.compile(
                r"\b(?:CBI|Central\s+Bureau\s+of\s+Investigation|Narcotics\s+Control\s+Bureau|"
                r"NCB|Cyber\s+Crime(?:\s+Cell)?|State\s+Police|Mumbai\s+Police|Delhi\s+Police|"
                r"Income\s+Tax\s+(?:Dept|Department)|IRS|Customs\s+(?:Dept|Department)|"
                r"Supreme\s+Court|High\s+Court|TRAI|Enforcement\s+Directorate|ED)\b",
                re.IGNORECASE,
            ),
            severity="medium",
            evidence_strength="high",
            reason="Claims representation of law enforcement, tax, or regulatory authority.",
        ),
        TacticRule(
            rule_id="imp_util_004",
            tactic="impersonation",
            pattern=re.compile(
                r"\b(?:Electricity\s+(?:Board|Dept|Department)|Power\s+Corporation|"
                r"Bijli\s+Vibhag|BSES|MSEDCL|Torrent\s+Power|Water\s+Board|Gas\s+Authority|"
                r"Indane|Bharat\s+Gas)\b",
                re.IGNORECASE,
            ),
            severity="medium",
            evidence_strength="medium",
            reason="Claims representation of a public utility or municipal service board.",
        ),
        TacticRule(
            rule_id="imp_tech_005",
            tactic="impersonation",
            pattern=re.compile(
                r"\b(?:Microsoft(?:\s+Support)?|Apple(?:\s+Support)?|Google(?:\s+Security)?|"
                r"Amazon(?:\s+Customer\s+Service)?|Netflix(?:\s+Support)?|Geek\s+Squad|"
                r"WhatsApp\s+Support|Telegram\s+Support)\b",
                re.IGNORECASE,
            ),
            severity="medium",
            evidence_strength="medium",
            reason="Claims representation of a major technology platform or customer support desk.",
        ),
        TacticRule(
            rule_id="imp_post_006",
            tactic="impersonation",
            pattern=re.compile(
                r"\b(?:India\s+Post|FedEx|BlueDart|DHL|USPS|UPS|Royal\s+Mail|Hermes|Evri)\b",
                re.IGNORECASE,
            ),
            severity="medium",
            evidence_strength="medium",
            reason="Claims representation of a postal or courier delivery service.",
        ),
        TacticRule(
            rule_id="imp_exec_007",
            tactic="impersonation",
            pattern=re.compile(
                r"\b(?:(?:this\s+is\s+your\s+CEO|this\s+is\s+the\s+manager|"
                r"hi\s+(?:mom|dad|mum),?\s+this\s+is\s+my\s+new\s+number|"
                r"hi\s+(?:mom|dad),?\s+(?:lost|broke)\s+my\s+phone))\b",
                re.IGNORECASE,
            ),
            severity="medium",
            evidence_strength="high",
            reason="Impersonates an executive, manager, or immediate family member.",
        ),
        TacticRule(
            rule_id="imp_customer_008",
            tactic="impersonation",
            pattern=re.compile(
                r"\b(?:as\s+a\s+valued\s+(?:network\s+)?customer|customer\s+service\s+representative|"
                r"account\s+statement\s+for|your\s+200\d\s+account\s+statement)\b",
                re.IGNORECASE,
            ),
            severity="medium",
            evidence_strength="medium",
            reason="Claims representation of an official customer service desk or network operator.",
        ),

        # =========================================================================
        # 2. URGENCY (severity: medium)
        # =========================================================================
        TacticRule(
            rule_id="urg_action_001",
            tactic="urgency",
            pattern=re.compile(
                r"\b(?:immediately|urgent(?:ly)?|act\s+now|right\s+now|without\s+delay|"
                r"at\s+once|promptly|hurry(?:\s+up)?|time\s+is\s+running\s+out|do\s+not\s+delay)\b",
                re.IGNORECASE,
            ),
            severity="medium",
            evidence_strength="high",
            reason="Pressures the recipient to act immediately without delay.",
        ),
        TacticRule(
            rule_id="urg_deadline_002",
            tactic="urgency",
            pattern=re.compile(
                r"\b(?:within\s+(?:\d+|24|12|48|2|1)\s*(?:hours?|hrs?|mins?|minutes?)|"
                r"expires\s+(?:today|tonight|in\s+\d+\s*hours?)|valid\s+(?:for\s+)?today\s+only|"
                r"last\s+chance|before\s+it\s+is\s+too\s+late|limited\s+time\s+offer)\b",
                re.IGNORECASE,
            ),
            severity="medium",
            evidence_strength="high",
            reason="Imposes a strict ticking countdown or expiration deadline.",
        ),
        TacticRule(
            rule_id="urg_cutoff_003",
            tactic="urgency",
            pattern=re.compile(
                r"\b(?:will\s+be\s+(?:blocked|suspended|disconnected|cut|terminated)\s+"
                r"(?:today|tonight|immediately|at\s+\d+(?::\d+)?\s*(?:pm|am)?))\b",
                re.IGNORECASE,
            ),
            severity="medium",
            evidence_strength="high",
            reason="Warns of service cutoff or termination within the day or night.",
        ),
        TacticRule(
            rule_id="urg_sms_004",
            tactic="urgency",
            pattern=re.compile(
                r"\b(?:valid\s+\d+\s*(?:hours?|hrs?)\s*(?:only)?|must\s+go|collect\s+yours?\s+today)\b",
                re.IGNORECASE,
            ),
            severity="medium",
            evidence_strength="high",
            reason="Imposes urgent redemption terms or immediate collection instructions.",
        ),

        # =========================================================================
        # 3. THREAT (severity: medium)
        # =========================================================================
        TacticRule(
            rule_id="thr_legal_001",
            tactic="threat",
            pattern=re.compile(
                r"\b(?:warrant\s+for\s+your\s+arrest|arrest\s+warrant|will\s+be\s+arrested|"
                r"legal\s+action\s+will\s+be\s+taken|court\s+summons|police\s+complaint|"
                r"FIR\s+will\s+be\s+registered|police\s+will\s+visit|prosecution\s+under\s+section)\b",
                re.IGNORECASE,
            ),
            severity="medium",
            evidence_strength="high",
            reason="Threatens legal prosecution, arrest, or police intervention.",
        ),
        TacticRule(
            rule_id="thr_financial_002",
            tactic="threat",
            pattern=re.compile(
                r"\b(?:assets\s+will\s+be\s+frozen|bank\s+account\s+will\s+be\s+seized|"
                r"heavy\s+penalty\s+of|penalty\s+charges\s+will\s+be\s+levied|"
                r"connection\s+will\s+be\s+permanently\s+terminated)\b",
                re.IGNORECASE,
            ),
            severity="medium",
            evidence_strength="high",
            reason="Threatens asset seizure, heavy penalties, or permanent service termination.",
        ),

        # =========================================================================
        # 4. FEAR_CREATION (severity: medium)
        # =========================================================================
        TacticRule(
            rule_id="fea_arrest_001",
            tactic="fear_creation",
            pattern=re.compile(
                r"\b(?:under\s+digital\s+arrest|illegal\s+parcel|narcotics\s+found|"
                r"drugs\s+found\s+in\s+parcel|linked\s+to\s+money\s+laundering|"
                r"terrorist\s+financing|illicit\s+substances\s+seized)\b",
                re.IGNORECASE,
            ),
            severity="medium",
            evidence_strength="high",
            reason="Falsely alleges involvement in serious crimes or claims digital arrest.",
        ),
        TacticRule(
            rule_id="fea_blackmail_002",
            tactic="fear_creation",
            pattern=re.compile(
                r"\b(?:recorded\s+you\s+through\s+(?:webcam|camera)|"
                r"recorded\s+(?:your\s+)?intimate\s+video|compromised\s+your\s+device|"
                r"caught\s+visiting\s+(?:adult|sensitive)\s+sites|"
                r"send\s+this\s+video\s+to\s+your\s+contacts)\b",
                re.IGNORECASE,
            ),
            severity="medium",
            evidence_strength="high",
            reason="Blackmails recipient with claims of recorded intimate footage or camera surveillance.",
        ),
        TacticRule(
            rule_id="fea_emergency_003",
            tactic="fear_creation",
            pattern=re.compile(
                r"\b(?:(?:son|daughter|family\s+member)\s+(?:met\s+with\s+an\s+accident|"
                r"is\s+in\s+icu|hospitalized\s+in\s+critical\s+condition|admitted\s+to\s+emergency))\b",
                re.IGNORECASE,
            ),
            severity="medium",
            evidence_strength="high",
            reason="Fabricates a medical catastrophe or critical accident involving a family member.",
        ),

        # =========================================================================
        # 5. AUTHORITY_CLAIM (severity: medium)
        # =========================================================================
        TacticRule(
            rule_id="aut_statutory_001",
            tactic="authority_claim",
            pattern=re.compile(
                r"\b(?:under\s+section\s+\d+[a-zA-Z]?|as\s+per\s+rbi\s+mandate|"
                r"by\s+order\s+of\s+(?:court|government)|government\s+directive|"
                r"statutory\s+notice|official\s+directive|judicial\s+order|"
                r"national\s+security\s+act)\b",
                re.IGNORECASE,
            ),
            severity="medium",
            evidence_strength="high",
            reason="Invokes statutory directives, penal sections, or governmental orders.",
        ),

        # =========================================================================
        # 6. PAYMENT_REQUEST (severity: high)
        # =========================================================================
        TacticRule(
            rule_id="pay_direct_001",
            tactic="payment_request",
            pattern=re.compile(
                r"\b(?:pay\s+(?:rs\.?|inr|\$|£|€)\s*\d+|transfer\s+(?:rs\.?|inr|\$)\s*\d+|"
                r"send\s+(?:rs\.?|inr|\$)\s*\d+|deposit\s+amount\s+of|pay\s+immediately|"
                r"make\s+payment|clear\s+your\s+dues|unpaid\s+bill\s+of)\b",
                re.IGNORECASE,
            ),
            severity="high",
            evidence_strength="high",
            reason="Solicits direct payment, remittance, or fee settlement.",
            negative_pattern=re.compile(
                r"\b(?:paid|receipt|credited|successful|payment\s+received)\b",
                re.IGNORECASE,
            ),
        ),
        TacticRule(
            rule_id="pay_fee_002",
            tactic="payment_request",
            pattern=re.compile(
                r"\b(?:processing\s+fee|customs\s+fee|clearance\s+fee|registration\s+fee|"
                r"send\s+bitcoin|send\s+0\.\d+\s*btc|crypto\s+wallet\s+address|"
                r"buy\s+(?:itunes|amazon|google\s+play)?\s*gift\s*cards?)\b",
                re.IGNORECASE,
            ),
            severity="high",
            evidence_strength="high",
            reason="Demands upfront processing fees, cryptocurrency transfers, or gift card purchases.",
        ),
        TacticRule(
            rule_id="pay_upi_003",
            tactic="payment_request",
            pattern=re.compile(
                r"\b(?:pay\s+via\s+upi|send\s+money\s+to\s+upi|upi\s+id\s+for\s+payment|"
                r"gpay\s+number|phonepe\s+number|paytm\s+number)\b",
                re.IGNORECASE,
            ),
            severity="high",
            evidence_strength="medium",
            reason="Instructs monetary remittance through UPI or digital wallets.",
            negative_pattern=re.compile(r"\b(?:received|cashback\s+credited)\b", re.IGNORECASE),
        ),
        TacticRule(
            rule_id="pay_carrier_004",
            tactic="payment_request",
            pattern=re.compile(
                r"\b(?:(?:cost|price)\s+\d+(?:p|ppm|ppw|gbp)|(?:\d+p(?:\/day|\/week|\/min|\/msg|pm|pw))|"
                r"(?:mobile\s+will\s+be\s+charged|charged\s+(?:£|\$|rs\.?)\s*\d+)|"
                r"(?:from\s+only\s+(?:£|\$|rs\.?)\s*\d+))\b",
                re.IGNORECASE,
            ),
            severity="high",
            evidence_strength="high",
            reason="Solicits recurring mobile charges or premium carrier rates.",
        ),

        # =========================================================================
        # 7. CREDENTIAL_REQUEST (severity: high)
        # =========================================================================
        TacticRule(
            rule_id="crd_pass_001",
            tactic="credential_request",
            pattern=re.compile(
                r"\b(?:enter\s+your\s+password|send\s+(?:your\s+)?password|share\s+your\s+pin|"
                r"atm\s+pin|upi\s+pin|netbanking\s+password|cvv\s+number|"
                r"card\s+expiry\s+and\s+cvv|security\s+questions?)\b",
                re.IGNORECASE,
            ),
            severity="high",
            evidence_strength="high",
            reason="Solicits sensitive authentication credentials, passwords, CVV, or PINs.",
            negative_pattern=re.compile(
                r"\b(?:never\s+share|do\s+not\s+share|don't\s+share)\b",
                re.IGNORECASE,
            ),
        ),
        TacticRule(
            rule_id="crd_seed_002",
            tactic="credential_request",
            pattern=re.compile(
                r"\b(?:seed\s+phrase|recovery\s+phrase|private\s+key|wallet\s+secret\s+key)\b",
                re.IGNORECASE,
            ),
            severity="high",
            evidence_strength="high",
            reason="Demands cryptographic recovery seed phrases or private keys.",
            negative_pattern=re.compile(
                r"\b(?:never\s+share|do\s+not\s+share)\b",
                re.IGNORECASE,
            ),
        ),

        # =========================================================================
        # 8. OTP_REQUEST (severity: high)
        # =========================================================================
        TacticRule(
            rule_id="otp_share_001",
            tactic="otp_request",
            pattern=re.compile(
                r"\b(?:share\s+(?:the\s+|your\s+)?otp|send\s+(?:the\s+|your\s+)?otp|"
                r"tell\s+(?:me\s+|the\s+|your\s+)?otp|provide\s+(?:the\s+|your\s+)?otp|"
                r"forward\s+(?:the\s+|your\s+)?otp|give\s+(?:the\s+|your\s+)?otp|"
                r"share\s+(?:the\s+)?(?:6-digit|4-digit)\s+(?:code|pin)|read\s+out\s+(?:the\s+)?otp)\b",
                re.IGNORECASE,
            ),
            severity="high",
            evidence_strength="high",
            reason="Explicitly requests the recipient to disclose or forward a One-Time Password.",
            negative_pattern=re.compile(
                r"\b(?:do\s+not\s+share|never\s+share|don't\s+share|use\s+the\s+otp|your\s+otp\s+is)\b",
                re.IGNORECASE,
            ),
        ),

        # =========================================================================
        # 9. PERSONAL_INFORMATION_REQUEST (severity: medium)
        # =========================================================================
        TacticRule(
            rule_id="pii_gov_001",
            tactic="personal_information_request",
            pattern=re.compile(
                r"\b(?:send\s+(?:your\s+)?(?:aadhaar|pan\s+card|ssn|social\s+security)|"
                r"provide\s+(?:your\s+)?(?:aadhaar|pan\s+number|passport\s+details|"
                r"date\s+of\s+birth|mother's\s+maiden\s+name))\b",
                re.IGNORECASE,
            ),
            severity="medium",
            evidence_strength="high",
            reason="Solicits government-issued identification numbers or sensitive personal details.",
        ),

        # =========================================================================
        # 10. ACCOUNT_SUSPENSION (severity: high)
        # =========================================================================
        TacticRule(
            rule_id="sus_account_001",
            tactic="account_suspension",
            pattern=re.compile(
                r"\b(?:account\s+will\s+be\s+(?:blocked|suspended|deactivated|closed|frozen)|"
                r"account\s+(?:is|has\s+been)\s+(?:blocked|suspended|deactivated|frozen)|"
                r"card\s+(?:has\s+been|will\s+be)\s+blocked|sim\s+card\s+will\s+be\s+deactivated)\b",
                re.IGNORECASE,
            ),
            severity="high",
            evidence_strength="high",
            reason="Warns that an account, bank card, or SIM card is or will be blocked or suspended.",
            negative_pattern=re.compile(r"\b(?:unblocked|re-activated|restored)\b", re.IGNORECASE),
        ),
        TacticRule(
            rule_id="sus_utility_002",
            tactic="account_suspension",
            pattern=re.compile(
                r"\b(?:(?:electricity|power|gas|broadband)\s+(?:connection\s+)?(?:will\s+be|has\s+been)\s+"
                r"(?:disconnected|cut\s+off|terminated))\b",
                re.IGNORECASE,
            ),
            severity="high",
            evidence_strength="high",
            reason="Warns of impending electricity or vital utility service disconnection.",
            negative_pattern=re.compile(r"\b(?:reconnected|restored)\b", re.IGNORECASE),
        ),

        # =========================================================================
        # 11. VERIFICATION_REQUEST (severity: medium)
        # =========================================================================
        TacticRule(
            rule_id="ver_kyc_001",
            tactic="verification_request",
            pattern=re.compile(
                r"\b(?:(?:verify|validate)\s+(?:your\s+)?(?:account|identity|details|profile|bank\s+account|kyc)|"
                r"(?:update|complete)\s+(?:your\s+)?kyc|kyc\s+(?:is\s+)?(?:pending|expired|suspended)|"
                r"link\s+(?:your\s+)?pan\s+(?:card\s+)?to\s+(?:your\s+)?account|"
                r"link\s+aadhaar\s+to\s+bank|re-verify\s+your\s+(?:sim|number))\b",
                re.IGNORECASE,
            ),
            severity="medium",
            evidence_strength="high",
            reason="Demands identity verification, KYC update, or account re-validation.",
            negative_pattern=re.compile(
                r"\b(?:successfully\s+verified|verification\s+complete|verified\s+successfully)\b",
                re.IGNORECASE,
            ),
        ),
        TacticRule(
            rule_id="ver_action_002",
            tactic="verification_request",
            pattern=re.compile(
                r"\b(?:(?:simply\s+)?text\s+.*to\s+verify|age\s+verify(?:\s+with)?|"
                r"activate\s+your\s+\d+|identifier\s+code\s*:\s*\d+)\b",
                re.IGNORECASE,
            ),
            severity="medium",
            evidence_strength="high",
            reason="Prompts recipient to verify age, activate promotions, or input verification identifiers.",
        ),

        # =========================================================================
        # 12. REWARD_CLAIM (severity: low)
        # =========================================================================
        TacticRule(
            rule_id="rew_prize_001",
            tactic="reward_claim",
            pattern=re.compile(
                r"\b(?:(?:congratulations|congrats),?\s+you\s+(?:have\s+)?(?:won|been\s+selected)|"
                r"won\s+(?:a\s+)?(?:lottery|jackpot|cash\s+prize|car|iphone)|"
                r"won\s+(?:rs\.?|inr|\$|£)\s*\d+|kbc\s+lucky\s+draw|selected\s+to\s+receive|"
                r"claim\s+your\s+(?:prize|reward|gift)|lucky\s+winner|prize\s+reward|"
                r"cashback\s+of\s+(?:rs\.?|inr|\$))\b",
                re.IGNORECASE,
            ),
            severity="low",
            evidence_strength="high",
            reason="Promises an unearned lottery win, prize, cashback, or windfall.",
            negative_pattern=re.compile(
                r"\b(?:congratulations\s+on\s+completing\s+your\s+purchase|earned\s+\d+\s+points)\b",
                re.IGNORECASE,
            ),
        ),
        TacticRule(
            rule_id="rew_bonus_002",
            tactic="reward_claim",
            pattern=re.compile(
                r"\b(?:(?:ur|you\s+are)\s+awarded|awarded\s+(?:with\s+a\s+|a\s+)?(?:complimentary|bonus|\d+|trip|prize)|"
                r"(?:bonus\s+prize|bonus\s+points|unredeemed\s+(?:bonus\s+)?points)|"
                r"(?:gift\s+guaranteed|guaranteed\s+(?:£|\$|rs\.?|cash|prize))|"
                r"(?:vouchers?\s+to\s+be\s+won|chances?\s+to\s+win(?:\s+cash)?|"
                r"free\s+entry(?:\s+into|\s+2|\s+to)?(?:\s+our)?(?:\s+weekly)?\s+draw)|"
                r"free\s+ringtone|free\s+text\s+messages?|specially\s+selected\s+(?:2|to)\s+receive)\b",
                re.IGNORECASE,
            ),
            severity="low",
            evidence_strength="high",
            reason="Promises unearned bonus points, guaranteed gifts, or competition draw entries.",
        ),

        # =========================================================================
        # 13. INVESTMENT_PRESSURE (severity: medium)
        # =========================================================================
        TacticRule(
            rule_id="inv_crypto_001",
            tactic="investment_pressure",
            pattern=re.compile(
                r"\b(?:guaranteed\s+(?:return|profit|daily\s+income)|earn\s+\d+%\s+daily|"
                r"earn\s+\d+%\s+weekly|double\s+your\s+money|risk-free\s+investment|"
                r"crypto\s+(?:trading\s+)?bot|vip\s+trading\s+group|insider\s+trading\s+tips|"
                r"pre-ipo\s+allocation|forex\s+trading\s+signals)\b",
                re.IGNORECASE,
            ),
            severity="medium",
            evidence_strength="high",
            reason="Promotes unrealistic, guaranteed, or high-pressure investment returns.",
        ),

        # =========================================================================
        # 14. JOB_OFFER (severity: low)
        # =========================================================================
        TacticRule(
            rule_id="job_task_001",
            tactic="job_offer",
            pattern=re.compile(
                r"\b(?:part-time\s+job|work\s+from\s+home\s+job|earn\s+(?:rs\.?|\$)\s*\d+\s*(?:daily|per\s+day)|"
                r"earn\s+daily\s+income|like\s+youtube\s+videos\s+and\s+earn|hotel\s+review\s+job|"
                r"data\s+entry\s+job\s+available|typing\s+job|daily\s+payouts?\s+guaranteed|"
                r"simple\s+online\s+task)\b",
                re.IGNORECASE,
            ),
            severity="low",
            evidence_strength="high",
            reason="Offers high-paying, minimal-effort remote tasks or employment opportunities.",
            negative_pattern=re.compile(
                r"\b(?:thank\s+you\s+for\s+applying|interview\s+schedule)\b",
                re.IGNORECASE,
            ),
        ),

        # =========================================================================
        # 15. EMOTIONAL_MANIPULATION (severity: medium)
        # =========================================================================
        TacticRule(
            rule_id="emo_plea_001",
            tactic="emotional_manipulation",
            pattern=re.compile(
                r"\b(?:stranded\s+without\s+money|please\s+help\s+me\s+urgently|"
                r"in\s+urgent\s+need\s+of\s+help|matter\s+of\s+life\s+and\s+death|"
                r"begging\s+you\s+to\s+help|have\s+no\s+one\s+else\s+to\s+turn\s+to|have\s+mercy)\b",
                re.IGNORECASE,
            ),
            severity="medium",
            evidence_strength="high",
            reason="Exploits compassion, moral obligation, or pity to elicit compliance.",
        ),

        # =========================================================================
        # 16. SECRECY_REQUEST (severity: high)
        # =========================================================================
        TacticRule(
            rule_id="sec_confidential_001",
            tactic="secrecy_request",
            pattern=re.compile(
                r"\b(?:do\s+not\s+(?:inform|tell|discuss\s+with)\s+(?:anyone|family|police|bank|branch\s+manager)|"
                r"keep\s+this\s+(?:strictly\s+)?confidential|keep\s+this\s+between\s+us|"
                r"do\s+not\s+disclose|covert\s+investigation|secret\s+audit)\b",
                re.IGNORECASE,
            ),
            severity="high",
            evidence_strength="high",
            reason="Instructs recipient to conceal the interaction from family, advisors, or bank staff.",
        ),

        # =========================================================================
        # 17. ROMANCE_MANIPULATION (severity: medium)
        # =========================================================================
        TacticRule(
            rule_id="rom_love_001",
            tactic="romance_manipulation",
            pattern=re.compile(
                r"\b(?:my\s+(?:dearest\s+)?love|my\s+darling|want\s+to\s+marry\s+you|"
                r"fell\s+in\s+love\s+with\s+you|send\s+you\s+expensive\s+gifts\s+from\s+abroad|"
                r"customs\s+clearance\s+for\s+(?:gold|jewelry|parcel\s+sent\s+for\s+you)|"
                r"need\s+money\s+for\s+flight\s+ticket\s+to\s+meet\s+you)\b",
                re.IGNORECASE,
            ),
            severity="medium",
            evidence_strength="high",
            reason="Feigns romantic affection to manipulate trust for financial extortion.",
            negative_pattern=re.compile(
                r"\b(?:happy\s+anniversary|see\s+you\s+at\s+home)\b",
                re.IGNORECASE,
            ),
        ),
        TacticRule(
            rule_id="rom_chat_002",
            tactic="romance_manipulation",
            pattern=re.compile(
                r"\b(?:blind\s+date(?:\s+4u)?|dating\s+svc|chat\s+svc|why\s+haven't\s+you\s+replied|"
                r"i'm\s+(?:randy|sexy|horny|single)|meet\s+(?:singles|girls|women|men)\s+(?:near|local|in))\b",
                re.IGNORECASE,
            ),
            severity="medium",
            evidence_strength="high",
            reason="Lures recipient into adult dating services, provocative chat lines, or feigned intimacy.",
        ),

        # =========================================================================
        # 18. TECHNICAL_SUPPORT_CLAIM (severity: medium)
        # =========================================================================
        TacticRule(
            rule_id="tec_virus_001",
            tactic="technical_support_claim",
            pattern=re.compile(
                r"\b(?:(?:computer\s+)?virus\s+(?:detected|found|alert|warning)?|"
                r"(?:trojan|malware|spyware)\s+detected|computer\s+(?:has\s+been\s+)?infected|"
                r"windows\s+defender\s+alert|call\s+(?:microsoft|apple|tech)\s+support|"
                r"firewall\s+breach|device\s+has\s+been\s+compromised|call\s+toll-free\s+support)\b",
                re.IGNORECASE,
            ),
            severity="medium",
            evidence_strength="high",
            reason="Falsely alleges a malware infection or security compromise requiring technical helpline contact.",
        ),

        # =========================================================================
        # 19. REFUND_CLAIM (severity: low)
        # =========================================================================
        TacticRule(
            rule_id="ref_claim_001",
            tactic="refund_claim",
            pattern=re.compile(
                r"\b(?:refund\s+of\s+(?:rs\.?|inr|\$|£)\s*\d+|claim\s+(?:your\s+)?refund|"
                r"accidental\s+(?:overpayment|charge)|charge\s+of\s+(?:rs\.?|\$)\s*\d+\s+will\s+be\s+refunded|"
                r"eligible\s+for\s+(?:tax\s+)?refund|refund\s+pending)\b",
                re.IGNORECASE,
            ),
            severity="low",
            evidence_strength="high",
            reason="Announces an alleged pending refund or accidental charge requiring recipient action.",
            negative_pattern=re.compile(
                r"\b(?:refund\s+(?:has\s+been\s+)?credited|processed\s+to\s+your\s+account)\b",
                re.IGNORECASE,
            ),
        ),

        # =========================================================================
        # 20. DELIVERY_PROBLEM (severity: low)
        # =========================================================================
        TacticRule(
            rule_id="del_held_001",
            tactic="delivery_problem",
            pattern=re.compile(
                r"\b(?:package\s+(?:could\s+not\s+be|failed\s+to\s+be)\s+delivered|"
                r"parcel\s+(?:held|delayed|pending)\s+at\s+(?:depot|customs)|incomplete\s+(?:street\s+)?address|"
                r"update\s+delivery\s+address|failed\s+delivery\s+attempt|customs\s+fee\s+for\s+parcel)\b",
                re.IGNORECASE,
            ),
            severity="low",
            evidence_strength="high",
            reason="Claims a parcel delivery failure or customs delay requiring immediate intervention.",
            negative_pattern=re.compile(
                r"\b(?:parcel\s+has\s+been\s+delivered|delivered\s+to\s+front\s+porch)\b",
                re.IGNORECASE,
            ),
        ),

        # =========================================================================
        # 21. QR_CODE_REQUEST (severity: medium)
        # =========================================================================
        TacticRule(
            rule_id="qr_scan_001",
            tactic="qr_code_request",
            pattern=re.compile(
                r"\b(?:scan\s+(?:this|the|attached)\s+qr\s*(?:code)?|"
                r"scan\s+qr\s+to\s+(?:receive|get|claim)\s+(?:money|payment|cashback)|"
                r"scan\s+to\s+accept\s+payment)\b",
                re.IGNORECASE,
            ),
            severity="medium",
            evidence_strength="high",
            reason="Instructs recipient to scan a QR code, frequently to fraudulently authorize a debit.",
        ),

        # =========================================================================
        # 22. REMOTE_ACCESS_REQUEST (severity: high)
        # =========================================================================
        TacticRule(
            rule_id="rem_tool_001",
            tactic="remote_access_request",
            pattern=re.compile(
                r"\b(?:(?:install|download)\s+(?:anydesk|teamviewer|quicksupport|rustdesk|ultraviewer|zoho\s+assist)|"
                r"grant\s+screen\s*sharing|remote\s+desktop\s+access)\b",
                re.IGNORECASE,
            ),
            severity="high",
            evidence_strength="high",
            reason="Requests installation of remote screen-sharing or remote desktop management software.",
        ),

        # =========================================================================
        # 23. LINK_REDIRECTION (severity: medium)
        # =========================================================================
        TacticRule(
            rule_id="lnk_click_001",
            tactic="link_redirection",
            pattern=re.compile(
                r"\b(?:click\s+(?:here|this\s+link|the\s+link|link\s+below)|"
                r"visit\s+(?:this\s+)?link|open\s+(?:this\s+)?link|follow\s+this\s+link|"
                r"tap\s+(?:here|on\s+link)|download\s+(?:from\s+)?link)\b",
                re.IGNORECASE,
            ),
            severity="medium",
            evidence_strength="medium",
            reason="Urges the recipient to click or open an external hyperlink.",
        ),
        TacticRule(
            rule_id="lnk_url_002",
            tactic="link_redirection",
            pattern=re.compile(
                r"(?:https?://[^\s]+|www\.[a-zA-Z0-9-]+\.[a-zA-Z]{2,}(?:/[^\s]*)?|"
                r"(?:goto\s+)?wap\.[a-zA-Z0-9-]+\.[a-zA-Z]{2,}|"
                r"(?:bit\.ly|tinyurl\.com|t\.me|wa\.me|cutt\.ly|is\.gd)/[^\s]+)",
                re.IGNORECASE,
            ),
            severity="medium",
            evidence_strength="high",
            reason="Contains an embedded URL, shortened link, or redirection link.",
        ),
    ]

    return rules
