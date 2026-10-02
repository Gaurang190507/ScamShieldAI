"""Creates the validated ScamShield AI Human Annotation Pilot Dataset (60 samples).

Applies rigorous human annotation according to annotation_guidelines.md:
- Differentiates scam intent from legitimate urgent or financial language (hard negatives)
- Grounded exact substring evidence spans
- Calibrated confidence and documentation of ambiguous / boundary cases
- Strict schema validation
"""

import json
from pathlib import Path
from typing import Dict, Any, List

from .dataset_schema import (
    Label,
    ScamCategory,
    RequestedAction,
    TargetAsset,
    UrgencyLevel,
    ImpersonatedEntity,
    LabelConfidence,
    KnownUnknownStatus,
)
from .dataset_validator import DatasetValidator


def create_annotated_pilot() -> List[Dict[str, Any]]:
    """Returns the 60 meticulously annotated pilot records."""
    root = Path(__file__).resolve().parents[2]
    template_file = root / "data" / "evaluation" / "annotation_pilot" / "annotation_template.jsonl"

    with open(template_file, "r", encoding="utf-8") as f:
        records = [json.loads(line) for line in f]

    annotated = []

    for r in records:
        sid = r["sample_id"]
        txt = r["text"]
        rec = dict(r)
        rec["annotator_id"] = "annotator_001"
        rec["pattern_group_id"] = "unknown"  # Documented unknown campaign group convention

        # -------------------------------------------------------------
        # 1. Benign Conversational Samples (15 samples)
        # -------------------------------------------------------------
        if sid in [
            "uci_sms_0001", "uci_sms_0002", "uci_sms_0004", "uci_sms_0005",
            "uci_sms_0007", "uci_sms_0008", "uci_sms_0011", "uci_sms_0014",
            "uci_sms_0015", "uci_sms_0018", "uci_sms_0019", "uci_sms_0021",
            "uci_sms_0022", "uci_sms_0023", "uci_sms_0024"
        ]:
            rec["label"] = Label.NON_SCAM.value
            rec["scam_category"] = ScamCategory.NONE.value
            rec["tactics"] = []
            rec["evidence_spans"] = []
            rec["requested_action"] = RequestedAction.NONE.value
            rec["target_asset"] = TargetAsset.NONE.value
            rec["urgency_level"] = UrgencyLevel.NONE.value
            rec["impersonated_entity"] = ImpersonatedEntity.NONE.value
            rec["label_confidence"] = LabelConfidence.HIGH.value
            rec["known_unknown_status"] = KnownUnknownStatus.KNOWN.value
            rec["notes"] = "Benign personal / conversational message. No deceptive intent or manipulation tactics."

        # -------------------------------------------------------------
        # 2. Hard Negatives: Urgency (8 samples)
        # -------------------------------------------------------------
        elif sid == "uci_sms_0029":
            # "I'm back &amp; we're packing the car now, I'll let you know if there's room"
            rec["label"] = Label.NON_SCAM.value
            rec["scam_category"] = ScamCategory.NONE.value
            rec["tactics"] = []
            rec["evidence_spans"] = []
            rec["requested_action"] = RequestedAction.NONE.value
            rec["target_asset"] = TargetAsset.NONE.value
            rec["urgency_level"] = UrgencyLevel.NONE.value
            rec["impersonated_entity"] = ImpersonatedEntity.NONE.value
            rec["label_confidence"] = LabelConfidence.HIGH.value
            rec["known_unknown_status"] = KnownUnknownStatus.KNOWN.value
            rec["notes"] = "Hard negative: contains conversational 'now' describing packing logistics, not artificial coercion."

        elif sid == "uci_sms_0034":
            # "For fear of fainting with the of all that housework you just did? Quick have a cuppa"
            rec["label"] = Label.NON_SCAM.value
            rec["scam_category"] = ScamCategory.NONE.value
            rec["tactics"] = []
            rec["evidence_spans"] = []
            rec["requested_action"] = RequestedAction.NONE.value
            rec["target_asset"] = TargetAsset.NONE.value
            rec["urgency_level"] = UrgencyLevel.NONE.value
            rec["impersonated_entity"] = ImpersonatedEntity.NONE.value
            rec["label_confidence"] = LabelConfidence.HIGH.value
            rec["known_unknown_status"] = KnownUnknownStatus.KNOWN.value
            rec["notes"] = "Hard negative: friendly joke using 'fear' and 'Quick', but zero malicious tactics."

        elif sid == "uci_sms_0056":
            # "Do you know what Mallika Sherawat did yesterday? Find out now @  &lt;URL&gt;"
            # Celebrity gossip clickbait promo
            rec["label"] = Label.NON_SCAM.value
            rec["scam_category"] = ScamCategory.NONE.value
            rec["tactics"] = ["urgency", "link_redirection"]
            rec["evidence_spans"] = [
                {"tactic": "urgency", "evidence": "now"},
                {"tactic": "link_redirection", "evidence": "&lt;URL&gt;"},
            ]
            rec["requested_action"] = RequestedAction.CLICK_LINK.value
            rec["target_asset"] = TargetAsset.NONE.value
            rec["urgency_level"] = UrgencyLevel.LOW.value
            rec["impersonated_entity"] = ImpersonatedEntity.NONE.value
            rec["label_confidence"] = LabelConfidence.MEDIUM.value
            rec["known_unknown_status"] = KnownUnknownStatus.KNOWN.value
            rec["notes"] = "Hard negative: promotional media clickbait with link redirection and mild urgency, but not a financial scam."

        elif sid == "uci_sms_0064":
            # "Sorry my roommates took forever, it ok if I come by now?"
            rec["label"] = Label.NON_SCAM.value
            rec["scam_category"] = ScamCategory.NONE.value
            rec["tactics"] = []
            rec["evidence_spans"] = []
            rec["requested_action"] = RequestedAction.REPLY.value
            rec["target_asset"] = TargetAsset.NONE.value
            rec["urgency_level"] = UrgencyLevel.NONE.value
            rec["impersonated_entity"] = ImpersonatedEntity.NONE.value
            rec["label_confidence"] = LabelConfidence.HIGH.value
            rec["known_unknown_status"] = KnownUnknownStatus.KNOWN.value
            rec["notes"] = "Hard negative: conversational scheduling question using 'now'."

        elif sid == "uci_sms_0067":
            # "Today is \"song dedicated day..\" Which song will u dedicate for me? Send this to all ur valuable frnds but first rply me..."
            rec["label"] = Label.NON_SCAM.value
            rec["scam_category"] = ScamCategory.NONE.value
            rec["tactics"] = []
            rec["evidence_spans"] = []
            rec["requested_action"] = RequestedAction.REPLY.value
            rec["target_asset"] = TargetAsset.NONE.value
            rec["urgency_level"] = UrgencyLevel.NONE.value
            rec["impersonated_entity"] = ImpersonatedEntity.NONE.value
            rec["label_confidence"] = LabelConfidence.HIGH.value
            rec["known_unknown_status"] = KnownUnknownStatus.KNOWN.value
            rec["notes"] = "Hard negative: viral SMS chain message asking for reply. Non-scam."

        elif sid == "uci_sms_0073":
            # "HI BABE IM AT HOME NOW WANNA DO SOMETHING? XX"
            rec["label"] = Label.NON_SCAM.value
            rec["scam_category"] = ScamCategory.NONE.value
            rec["tactics"] = []
            rec["evidence_spans"] = []
            rec["requested_action"] = RequestedAction.REPLY.value
            rec["target_asset"] = TargetAsset.NONE.value
            rec["urgency_level"] = UrgencyLevel.NONE.value
            rec["impersonated_entity"] = ImpersonatedEntity.NONE.value
            rec["label_confidence"] = LabelConfidence.HIGH.value
            rec["known_unknown_status"] = KnownUnknownStatus.KNOWN.value
            rec["notes"] = "Hard negative: casual social communication."

        elif sid == "uci_sms_0075":
            # "U can call me now..."
            rec["label"] = Label.NON_SCAM.value
            rec["scam_category"] = ScamCategory.NONE.value
            rec["tactics"] = []
            rec["evidence_spans"] = []
            rec["requested_action"] = RequestedAction.CALL_PHONE_NUMBER.value
            rec["target_asset"] = TargetAsset.NONE.value
            rec["urgency_level"] = UrgencyLevel.NONE.value
            rec["impersonated_entity"] = ImpersonatedEntity.NONE.value
            rec["label_confidence"] = LabelConfidence.HIGH.value
            rec["known_unknown_status"] = KnownUnknownStatus.KNOWN.value
            rec["notes"] = "Hard negative: interpersonal callback request."

        elif sid == "uci_sms_0076":
            # "I am waiting machan. Call me once you free."
            rec["label"] = Label.NON_SCAM.value
            rec["scam_category"] = ScamCategory.NONE.value
            rec["tactics"] = []
            rec["evidence_spans"] = []
            rec["requested_action"] = RequestedAction.CALL_PHONE_NUMBER.value
            rec["target_asset"] = TargetAsset.NONE.value
            rec["urgency_level"] = UrgencyLevel.NONE.value
            rec["impersonated_entity"] = ImpersonatedEntity.NONE.value
            rec["label_confidence"] = LabelConfidence.HIGH.value
            rec["known_unknown_status"] = KnownUnknownStatus.KNOWN.value
            rec["notes"] = "Hard negative: friendly Indian slang ('machan') callback reminder."

        # -------------------------------------------------------------
        # 3. Hard Negatives: Financial / Billing (7 samples)
        # -------------------------------------------------------------
        elif sid == "uci_sms_0098":
            # "i see. When we finish we have loads of loans to pay"
            rec["label"] = Label.NON_SCAM.value
            rec["scam_category"] = ScamCategory.NONE.value
            rec["tactics"] = []
            rec["evidence_spans"] = []
            rec["requested_action"] = RequestedAction.NONE.value
            rec["target_asset"] = TargetAsset.NONE.value
            rec["urgency_level"] = UrgencyLevel.NONE.value
            rec["impersonated_entity"] = ImpersonatedEntity.NONE.value
            rec["label_confidence"] = LabelConfidence.HIGH.value
            rec["known_unknown_status"] = KnownUnknownStatus.KNOWN.value
            rec["notes"] = "Hard negative: personal financial discussion about student/personal loans."

        elif sid == "uci_sms_0131":
            # "K..k:)how much does it cost?"
            rec["label"] = Label.NON_SCAM.value
            rec["scam_category"] = ScamCategory.NONE.value
            rec["tactics"] = []
            rec["evidence_spans"] = []
            rec["requested_action"] = RequestedAction.REPLY.value
            rec["target_asset"] = TargetAsset.NONE.value
            rec["urgency_level"] = UrgencyLevel.NONE.value
            rec["impersonated_entity"] = ImpersonatedEntity.NONE.value
            rec["label_confidence"] = LabelConfidence.HIGH.value
            rec["known_unknown_status"] = KnownUnknownStatus.KNOWN.value
            rec["notes"] = "Hard negative: casual inquiry regarding cost."

        elif sid == "uci_sms_0172":
            # "Sir, I need AXIS BANK account no and bank address."
            rec["label"] = Label.NON_SCAM.value
            rec["scam_category"] = ScamCategory.NONE.value
            rec["tactics"] = ["personal_information_request"]
            rec["evidence_spans"] = [
                {"tactic": "personal_information_request", "evidence": "I need AXIS BANK account no and bank address"}
            ]
            rec["requested_action"] = RequestedAction.SHARE_BANK_DETAILS.value
            rec["target_asset"] = TargetAsset.BANK_ACCOUNT.value
            rec["urgency_level"] = UrgencyLevel.NONE.value
            rec["impersonated_entity"] = ImpersonatedEntity.NONE.value
            rec["label_confidence"] = LabelConfidence.MEDIUM.value
            rec["known_unknown_status"] = KnownUnknownStatus.KNOWN.value
            rec["notes"] = "Hard negative: requests bank coordinates for wire transfer, but lacks deceptive coercion; labelled non_scam."

        elif sid == "uci_sms_0193":
            # "I'm sorry. I've joined the league of people that dont keep in touch... even at great personal cost. Do have a great week.|"
            rec["label"] = Label.NON_SCAM.value
            rec["scam_category"] = ScamCategory.NONE.value
            rec["tactics"] = []
            rec["evidence_spans"] = []
            rec["requested_action"] = RequestedAction.NONE.value
            rec["target_asset"] = TargetAsset.NONE.value
            rec["urgency_level"] = UrgencyLevel.NONE.value
            rec["impersonated_entity"] = ImpersonatedEntity.NONE.value
            rec["label_confidence"] = LabelConfidence.HIGH.value
            rec["known_unknown_status"] = KnownUnknownStatus.KNOWN.value
            rec["notes"] = "Hard negative: figurative use of 'cost' in a heartfelt friendship apology."

        elif sid == "uci_sms_0204":
            # "Your account has been refilled successfully by INR  &lt;DECIMAL&gt; . Your KeralaCircle prepaid account balance is Rs  &lt;DECIMAL&gt; . Your Transaction ID is KR &lt;#&gt; ."
            rec["label"] = Label.NON_SCAM.value
            rec["scam_category"] = ScamCategory.NONE.value
            rec["tactics"] = []
            rec["evidence_spans"] = []
            rec["requested_action"] = RequestedAction.NONE.value
            rec["target_asset"] = TargetAsset.NONE.value
            rec["urgency_level"] = UrgencyLevel.NONE.value
            rec["impersonated_entity"] = ImpersonatedEntity.NONE.value
            rec["label_confidence"] = LabelConfidence.HIGH.value
            rec["known_unknown_status"] = KnownUnknownStatus.KNOWN.value
            rec["notes"] = "Hard negative: legitimate telecom service top-up receipt notification."

        elif sid == "uci_sms_0210":
            # "You please give us connection today itself before  &lt;DECIMAL&gt;  or refund the bill"
            rec["label"] = Label.NON_SCAM.value
            rec["scam_category"] = ScamCategory.NONE.value
            rec["tactics"] = ["urgency", "refund_claim"]
            rec["evidence_spans"] = [
                {"tactic": "urgency", "evidence": "today itself"},
                {"tactic": "refund_claim", "evidence": "refund the bill"},
            ]
            rec["requested_action"] = RequestedAction.REPLY.value
            rec["target_asset"] = TargetAsset.MONEY.value
            rec["urgency_level"] = UrgencyLevel.MEDIUM.value
            rec["impersonated_entity"] = ImpersonatedEntity.NONE.value
            rec["label_confidence"] = LabelConfidence.HIGH.value
            rec["known_unknown_status"] = KnownUnknownStatus.KNOWN.value
            rec["notes"] = "Hard negative: consumer grievance demanding broadband restoration or refund. Legitimate dispute."

        elif sid == "uci_sms_0375":
            # "I cant keep talking to people if am not sure i can pay them if they agree to price. So pls tell me what you want to really buy and how much you are willing to pay"
            rec["label"] = Label.NON_SCAM.value
            rec["scam_category"] = ScamCategory.NONE.value
            rec["tactics"] = []
            rec["evidence_spans"] = []
            rec["requested_action"] = RequestedAction.REPLY.value
            rec["target_asset"] = TargetAsset.MONEY.value
            rec["urgency_level"] = UrgencyLevel.NONE.value
            rec["impersonated_entity"] = ImpersonatedEntity.NONE.value
            rec["label_confidence"] = LabelConfidence.HIGH.value
            rec["known_unknown_status"] = KnownUnknownStatus.KNOWN.value
            rec["notes"] = "Hard negative: legitimate commercial price negotiation between buyer and seller."

        # -------------------------------------------------------------
        # 4. Scams with URLs (12 samples)
        # -------------------------------------------------------------
        elif sid == "uci_sms_0013":
            # "URGENT! You have won a 1 week FREE membership in our 100,000 Prize Jackpot! Txt the word: CLAIM to No: 81010 T&C www.dbuk.net LCCLTD POBOX 4403LDNW1A7RW18"
            rec["label"] = Label.SCAM.value
            rec["scam_category"] = ScamCategory.PHISHING.value
            rec["tactics"] = ["urgency", "reward_claim", "link_redirection"]
            rec["evidence_spans"] = [
                {"tactic": "urgency", "evidence": "URGENT!"},
                {"tactic": "reward_claim", "evidence": "won a 1 week FREE membership in our"},
                {"tactic": "link_redirection", "evidence": "www.dbuk.net"},
            ]
            rec["requested_action"] = RequestedAction.CLICK_LINK.value
            rec["target_asset"] = TargetAsset.MONEY.value
            rec["urgency_level"] = UrgencyLevel.HIGH.value
            rec["impersonated_entity"] = ImpersonatedEntity.COMPANY.value
            rec["label_confidence"] = LabelConfidence.HIGH.value
            rec["known_unknown_status"] = KnownUnknownStatus.KNOWN.value
            rec["notes"] = "High-risk lottery jackpot lure combining urgency and external URL."

        elif sid == "uci_sms_0016":
            # "XXXMobileMovieClub: To use your credit, click the WAP link in the next txt message or click here>> http://wap. xxxmobilemovieclub.com?n=QJKGIGHJJGCBL"
            rec["label"] = Label.SCAM.value
            rec["scam_category"] = ScamCategory.PHISHING.value
            rec["tactics"] = ["link_redirection", "reward_claim"]
            rec["evidence_spans"] = [
                {"tactic": "link_redirection", "evidence": "click the WAP link"},
                {"tactic": "reward_claim", "evidence": "To use your credit"},
            ]
            rec["requested_action"] = RequestedAction.CLICK_LINK.value
            rec["target_asset"] = TargetAsset.MONEY.value
            rec["urgency_level"] = UrgencyLevel.LOW.value
            rec["impersonated_entity"] = ImpersonatedEntity.COMPANY.value
            rec["label_confidence"] = LabelConfidence.HIGH.value
            rec["known_unknown_status"] = KnownUnknownStatus.KNOWN.value
            rec["notes"] = "Premium WAP billing lure directing user to external URL."

        elif sid == "uci_sms_0165":
            # "-PLS STOP bootydelious (32/F) is inviting you to be her friend. Reply YES-434 or NO-434 See her: www.SMS.ac/u/bootydelious STOP? Send STOP FRND to 62468"
            rec["label"] = Label.SCAM.value
            rec["scam_category"] = ScamCategory.ROMANCE.value
            rec["tactics"] = ["romance_manipulation", "link_redirection"]
            rec["evidence_spans"] = [
                {"tactic": "romance_manipulation", "evidence": "is inviting you to be her friend"},
                {"tactic": "link_redirection", "evidence": "www.SMS.ac/u/bootydelious"},
            ]
            rec["requested_action"] = RequestedAction.CLICK_LINK.value
            rec["target_asset"] = TargetAsset.MONEY.value
            rec["urgency_level"] = UrgencyLevel.LOW.value
            rec["impersonated_entity"] = ImpersonatedEntity.NONE.value
            rec["label_confidence"] = LabelConfidence.HIGH.value
            rec["known_unknown_status"] = KnownUnknownStatus.KNOWN.value
            rec["notes"] = "Social / romance hook soliciting paid SMS replies and site clicks."

        elif sid == "uci_sms_0192":
            # "Are you unique enough? Find out from 30th August. www.areyouunique.co.uk"
            rec["label"] = Label.NON_SCAM.value
            rec["scam_category"] = ScamCategory.NONE.value
            rec["tactics"] = ["link_redirection"]
            rec["evidence_spans"] = [
                {"tactic": "link_redirection", "evidence": "www.areyouunique.co.uk"}
            ]
            rec["requested_action"] = RequestedAction.CLICK_LINK.value
            rec["target_asset"] = TargetAsset.NONE.value
            rec["urgency_level"] = UrgencyLevel.NONE.value
            rec["impersonated_entity"] = ImpersonatedEntity.NONE.value
            rec["label_confidence"] = LabelConfidence.MEDIUM.value
            rec["known_unknown_status"] = KnownUnknownStatus.KNOWN.value
            rec["notes"] = "Promotional marketing teaser containing link; lacks fraud or coercion indicators. Non-scam."

        elif sid == "uci_sms_0226":
            # "500 New Mobiles from 2004, MUST GO! Txt: NOKIA to No: 89545 & collect yours today!From ONLY 1 www.4-tc.biz 2optout 087187262701.50gbp/mtmsg18"
            rec["label"] = Label.SCAM.value
            rec["scam_category"] = ScamCategory.SHOPPING.value
            rec["tactics"] = ["urgency", "reward_claim", "payment_request", "link_redirection"]
            rec["evidence_spans"] = [
                {"tactic": "urgency", "evidence": "MUST GO!"},
                {"tactic": "reward_claim", "evidence": "collect yours today!"},
                {"tactic": "payment_request", "evidence": "1.50gbp/mtmsg"},
                {"tactic": "link_redirection", "evidence": "www.4-tc.biz"},
            ]
            rec["requested_action"] = RequestedAction.CLICK_LINK.value
            rec["target_asset"] = TargetAsset.MONEY.value
            rec["urgency_level"] = UrgencyLevel.HIGH.value
            rec["impersonated_entity"] = ImpersonatedEntity.COMPANY.value
            rec["label_confidence"] = LabelConfidence.HIGH.value
            rec["known_unknown_status"] = KnownUnknownStatus.KNOWN.value
            rec["notes"] = "Deceptive mobile phone offer masking recurring high-rate SMS subscription."

        elif sid == "uci_sms_0251" or sid == "uci_sms_0358":
            # "Congratulations ur awarded 500 of CD vouchers or 125gift guaranteed & Free entry 2 100 wkly draw txt MUSIC to 87066 TnCs www.Ldew.com1win150ppmx3age16"
            rec["label"] = Label.SCAM.value
            rec["scam_category"] = ScamCategory.PHISHING.value
            rec["tactics"] = ["reward_claim", "payment_request", "link_redirection"]
            rec["evidence_spans"] = [
                {"tactic": "reward_claim", "evidence": "Congratulations ur awarded 500 of CD vouchers"},
                {"tactic": "payment_request", "evidence": "150ppm"},
                {"tactic": "link_redirection", "evidence": "www.Ldew.com"},
            ]
            rec["requested_action"] = RequestedAction.SEND_MONEY.value
            rec["target_asset"] = TargetAsset.MONEY.value
            rec["urgency_level"] = UrgencyLevel.LOW.value
            rec["impersonated_entity"] = ImpersonatedEntity.NONE.value
            rec["label_confidence"] = LabelConfidence.HIGH.value
            rec["known_unknown_status"] = KnownUnknownStatus.KNOWN.value
            rec["notes"] = "Prize voucher scheme charging hidden 150p/min fees."

        elif sid == "uci_sms_0274":
            # "HMV BONUS SPECIAL 500 pounds of genuine HMV vouchers to be won. Just answer 4 easy questions. Play Now! Send HMV to 86688 More info:www.100percent-real.com"
            rec["label"] = Label.SCAM.value
            rec["scam_category"] = ScamCategory.IMPERSONATION.value
            rec["tactics"] = ["impersonation", "reward_claim", "link_redirection"]
            rec["evidence_spans"] = [
                {"tactic": "impersonation", "evidence": "HMV"},
                {"tactic": "reward_claim", "evidence": "500 pounds of genuine HMV vouchers to be won"},
                {"tactic": "link_redirection", "evidence": "www.100percent-real.com"},
            ]
            rec["requested_action"] = RequestedAction.CLICK_LINK.value
            rec["target_asset"] = TargetAsset.MONEY.value
            rec["urgency_level"] = UrgencyLevel.LOW.value
            rec["impersonated_entity"] = ImpersonatedEntity.COMPANY.value
            rec["label_confidence"] = LabelConfidence.HIGH.value
            rec["known_unknown_status"] = KnownUnknownStatus.KNOWN.value
            rec["notes"] = "Retail brand impersonation promising unearned vouchers via suspicious URL."

        elif sid == "uci_sms_0306":
            # "SMS. ac Blind Date 4U!: Rodds1 is 21/m from Aberdeen, United Kingdom. Check Him out http://img. sms. ac/W/icmb3cktz8r7!-4 no Blind Dates send HIDE"
            rec["label"] = Label.SCAM.value
            rec["scam_category"] = ScamCategory.ROMANCE.value
            rec["tactics"] = ["romance_manipulation", "link_redirection"]
            rec["evidence_spans"] = [
                {"tactic": "romance_manipulation", "evidence": "Blind Date 4U!"},
                {"tactic": "link_redirection", "evidence": "http://img. sms. ac"},
            ]
            rec["requested_action"] = RequestedAction.CLICK_LINK.value
            rec["target_asset"] = TargetAsset.MONEY.value
            rec["urgency_level"] = UrgencyLevel.NONE.value
            rec["impersonated_entity"] = ImpersonatedEntity.NONE.value
            rec["label_confidence"] = LabelConfidence.MEDIUM.value
            rec["known_unknown_status"] = KnownUnknownStatus.KNOWN.value
            rec["notes"] = "Dating platform hook driving clicks to external image links."

        elif sid == "uci_sms_0369":
            # "Here is your discount code RP176781. To stop further messages reply stop. www.regalportfolio.co.uk. Customer Services 08717205546"
            rec["label"] = Label.NON_SCAM.value
            rec["scam_category"] = ScamCategory.NONE.value
            rec["tactics"] = ["link_redirection"]
            rec["evidence_spans"] = [
                {"tactic": "link_redirection", "evidence": "www.regalportfolio.co.uk"}
            ]
            rec["requested_action"] = RequestedAction.NONE.value
            rec["target_asset"] = TargetAsset.NONE.value
            rec["urgency_level"] = UrgencyLevel.NONE.value
            rec["impersonated_entity"] = ImpersonatedEntity.COMPANY.value
            rec["label_confidence"] = LabelConfidence.HIGH.value
            rec["known_unknown_status"] = KnownUnknownStatus.KNOWN.value
            rec["notes"] = "Commercial marketing discount message with opt-out instructions; classified as non_scam."

        elif sid == "uci_sms_0419":
            # "FREE entry into our 250 weekly competition just text the word WIN to 80086 NOW. 18 T&C www.txttowin.co.uk"
            rec["label"] = Label.SCAM.value
            rec["scam_category"] = ScamCategory.PHISHING.value
            rec["tactics"] = ["reward_claim", "urgency", "link_redirection"]
            rec["evidence_spans"] = [
                {"tactic": "reward_claim", "evidence": "FREE entry into our"},
                {"tactic": "urgency", "evidence": "NOW"},
                {"tactic": "link_redirection", "evidence": "www.txttowin.co.uk"},
            ]
            rec["requested_action"] = RequestedAction.REPLY.value
            rec["target_asset"] = TargetAsset.MONEY.value
            rec["urgency_level"] = UrgencyLevel.MEDIUM.value
            rec["impersonated_entity"] = ImpersonatedEntity.NONE.value
            rec["label_confidence"] = LabelConfidence.HIGH.value
            rec["known_unknown_status"] = KnownUnknownStatus.KNOWN.value
            rec["notes"] = "Deceptive competition text designed to hook subscriber into recurring carrier charges."

        elif sid == "uci_sms_0488":
            # "FREE MESSAGE Activate your 500 FREE Text Messages by replying to this message with the word FREE For terms & conditions, visit www.07781482378.com"
            rec["label"] = Label.SCAM.value
            rec["scam_category"] = ScamCategory.PHISHING.value
            rec["tactics"] = ["reward_claim", "verification_request", "link_redirection"]
            rec["evidence_spans"] = [
                {"tactic": "reward_claim", "evidence": "500 FREE Text Messages"},
                {"tactic": "verification_request", "evidence": "Activate your"},
                {"tactic": "link_redirection", "evidence": "www.07781482378.com"},
            ]
            rec["requested_action"] = RequestedAction.REPLY.value
            rec["target_asset"] = TargetAsset.MONEY.value
            rec["urgency_level"] = UrgencyLevel.LOW.value
            rec["impersonated_entity"] = ImpersonatedEntity.NONE.value
            rec["label_confidence"] = LabelConfidence.HIGH.value
            rec["known_unknown_status"] = KnownUnknownStatus.KNOWN.value
            rec["notes"] = "Fake network bonus bundle requiring activation reply and website visit."

        # -------------------------------------------------------------
        # 5. Scams with Lottery / Prizes (8 samples)
        # -------------------------------------------------------------
        elif sid == "uci_sms_0009":
            # "WINNER!! As a valued network customer you have been selected to receivea 900 prize reward! To claim call 09061701461. Claim code KL341. Valid 12 hours only."
            rec["label"] = Label.SCAM.value
            rec["scam_category"] = ScamCategory.IMPERSONATION.value
            rec["tactics"] = ["impersonation", "reward_claim", "urgency"]
            rec["evidence_spans"] = [
                {"tactic": "impersonation", "evidence": "valued network customer"},
                {"tactic": "reward_claim", "evidence": "receivea"},
                {"tactic": "urgency", "evidence": "Valid 12 hours only"},
            ]
            rec["requested_action"] = RequestedAction.CALL_PHONE_NUMBER.value
            rec["target_asset"] = TargetAsset.MONEY.value
            rec["urgency_level"] = UrgencyLevel.HIGH.value
            rec["impersonated_entity"] = ImpersonatedEntity.COMPANY.value
            rec["label_confidence"] = LabelConfidence.HIGH.value
            rec["known_unknown_status"] = KnownUnknownStatus.KNOWN.value
            rec["notes"] = "Impersonation of telecom network operator promising prize reward with strict 12hr deadline."

        elif sid == "uci_sms_0012":
            # "SIX chances to win CASH! From 100 to 20,000 pounds txt> CSH11 and send to 87575. Cost 150p/day, 6days, 16+ TsandCs apply Reply HL 4 info"
            rec["label"] = Label.SCAM.value
            rec["scam_category"] = ScamCategory.INVESTMENT.value
            rec["tactics"] = ["reward_claim", "payment_request"]
            rec["evidence_spans"] = [
                {"tactic": "reward_claim", "evidence": "chances to win CASH!"},
                {"tactic": "payment_request", "evidence": "Cost 150p/day"},
            ]
            rec["requested_action"] = RequestedAction.SEND_MONEY.value
            rec["target_asset"] = TargetAsset.MONEY.value
            rec["urgency_level"] = UrgencyLevel.LOW.value
            rec["impersonated_entity"] = ImpersonatedEntity.NONE.value
            rec["label_confidence"] = LabelConfidence.HIGH.value
            rec["known_unknown_status"] = KnownUnknownStatus.KNOWN.value
            rec["notes"] = "Cash competition lure with premium rate billing terms."

        elif sid == "uci_sms_0066":
            # "As a valued customer, I am pleased to advise you that following recent review of your Mob No. you are awarded with a 1500 Bonus Prize, call 09066364589"
            rec["label"] = Label.SCAM.value
            rec["scam_category"] = ScamCategory.IMPERSONATION.value
            rec["tactics"] = ["impersonation", "reward_claim"]
            rec["evidence_spans"] = [
                {"tactic": "impersonation", "evidence": "valued customer"},
                {"tactic": "reward_claim", "evidence": "awarded with a"},
            ]
            rec["requested_action"] = RequestedAction.CALL_PHONE_NUMBER.value
            rec["target_asset"] = TargetAsset.MONEY.value
            rec["urgency_level"] = UrgencyLevel.LOW.value
            rec["impersonated_entity"] = ImpersonatedEntity.COMPANY.value
            rec["label_confidence"] = LabelConfidence.HIGH.value
            rec["known_unknown_status"] = KnownUnknownStatus.KNOWN.value
            rec["notes"] = "Operator impersonation awarding unearned bonus prize via premium rate telephone line."

        elif sid == "uci_sms_0068":
            # "Urgent UR awarded a complimentary trip to EuroDisinc Trav, Aco&Entry41 Or 1000. To claim txt DIS to 87121 18+6*1.50(moreFrmMob. ShrAcomOrSglSuplt)10, LS1 3AJ"
            rec["label"] = Label.SCAM.value
            rec["scam_category"] = ScamCategory.PHISHING.value
            rec["tactics"] = ["urgency", "reward_claim", "payment_request"]
            rec["evidence_spans"] = [
                {"tactic": "urgency", "evidence": "Urgent"},
                {"tactic": "reward_claim", "evidence": "awarded a complimentary trip"},
                {"tactic": "payment_request", "evidence": "6*"},
            ]
            rec["requested_action"] = RequestedAction.REPLY.value
            rec["target_asset"] = TargetAsset.MONEY.value
            rec["urgency_level"] = UrgencyLevel.HIGH.value
            rec["impersonated_entity"] = ImpersonatedEntity.NONE.value
            rec["label_confidence"] = LabelConfidence.HIGH.value
            rec["known_unknown_status"] = KnownUnknownStatus.KNOWN.value
            rec["notes"] = "Urgent holiday travel prize lure hiding premium SMS tariff."

        elif sid == "uci_sms_0094":
            # "Please call our customer service representative on 0800 169 6031 between 10am-9pm as you have WON a guaranteed 1000 cash or 5000 prize!"
            rec["label"] = Label.SCAM.value
            rec["scam_category"] = ScamCategory.TECHNICAL_SUPPORT.value
            rec["tactics"] = ["impersonation", "reward_claim"]
            rec["evidence_spans"] = [
                {"tactic": "impersonation", "evidence": "customer service representative"},
                {"tactic": "reward_claim", "evidence": "WON a guaranteed"},
            ]
            rec["requested_action"] = RequestedAction.CALL_PHONE_NUMBER.value
            rec["target_asset"] = TargetAsset.MONEY.value
            rec["urgency_level"] = UrgencyLevel.LOW.value
            rec["impersonated_entity"] = ImpersonatedEntity.CUSTOMER_SUPPORT.value
            rec["label_confidence"] = LabelConfidence.HIGH.value
            rec["known_unknown_status"] = KnownUnknownStatus.KNOWN.value
            rec["notes"] = "Fake customer support helpline claiming guaranteed cash prize."

        elif sid == "uci_sms_0115":
            # "GENT! We are trying to contact you. Last weekends draw shows that you won a 1000 prize GUARANTEED. Call 09064012160. Claim Code K52. Valid 12hrs only. 150ppm"
            rec["label"] = Label.SCAM.value
            rec["scam_category"] = ScamCategory.PHISHING.value
            rec["tactics"] = ["urgency", "reward_claim", "payment_request"]
            rec["evidence_spans"] = [
                {"tactic": "urgency", "evidence": "Valid 12hrs only"},
                {"tactic": "reward_claim", "evidence": "won a"},
                {"tactic": "payment_request", "evidence": "150ppm"},
            ]
            rec["requested_action"] = RequestedAction.CALL_PHONE_NUMBER.value
            rec["target_asset"] = TargetAsset.MONEY.value
            rec["urgency_level"] = UrgencyLevel.HIGH.value
            rec["impersonated_entity"] = ImpersonatedEntity.NONE.value
            rec["label_confidence"] = LabelConfidence.HIGH.value
            rec["known_unknown_status"] = KnownUnknownStatus.KNOWN.value
            rec["notes"] = "High urgency lottery jackpot scam charging 150p per minute."

        elif sid == "uci_sms_0118":
            # "You are a winner U have been specially selected 2 receive 1000 or a 4* holiday (flights inc) speak to a live operator 2 claim 0871277810910p/min (18+)"
            rec["label"] = Label.SCAM.value
            rec["scam_category"] = ScamCategory.PHISHING.value
            rec["tactics"] = ["reward_claim", "payment_request"]
            rec["evidence_spans"] = [
                {"tactic": "reward_claim", "evidence": "specially selected 2 receive"},
                {"tactic": "payment_request", "evidence": "10p/min"},
            ]
            rec["requested_action"] = RequestedAction.CALL_PHONE_NUMBER.value
            rec["target_asset"] = TargetAsset.MONEY.value
            rec["urgency_level"] = UrgencyLevel.LOW.value
            rec["impersonated_entity"] = ImpersonatedEntity.NONE.value
            rec["label_confidence"] = LabelConfidence.HIGH.value
            rec["known_unknown_status"] = KnownUnknownStatus.KNOWN.value
            rec["notes"] = "Fake sweepstakes prize requiring call to expensive live operator line."

        elif sid == "uci_sms_0121":
            # "PRIVATE! Your 2004 Account Statement for 07742676969 shows 786 unredeemed Bonus Points. To claim call 08719180248 Identifier Code: 45239 Expires"
            rec["label"] = Label.SCAM.value
            rec["scam_category"] = ScamCategory.IMPERSONATION.value
            rec["tactics"] = ["impersonation", "reward_claim", "urgency", "verification_request"]
            rec["evidence_spans"] = [
                {"tactic": "impersonation", "evidence": "Account Statement"},
                {"tactic": "reward_claim", "evidence": "unredeemed Bonus Points"},
                {"tactic": "urgency", "evidence": "Expires"},
                {"tactic": "verification_request", "evidence": "Identifier Code: 45239"},
            ]
            rec["requested_action"] = RequestedAction.CALL_PHONE_NUMBER.value
            rec["target_asset"] = TargetAsset.MONEY.value
            rec["urgency_level"] = UrgencyLevel.MEDIUM.value
            rec["impersonated_entity"] = ImpersonatedEntity.COMPANY.value
            rec["label_confidence"] = LabelConfidence.HIGH.value
            rec["known_unknown_status"] = KnownUnknownStatus.KNOWN.value
            rec["notes"] = "Deceptive statement impersonation with bonus points expiry pretext."

        # -------------------------------------------------------------
        # 6. Commercial Spam Boundary (5 samples)
        # -------------------------------------------------------------
        elif sid == "uci_sms_0035":
            # "Thanks for your subscription to Ringtone UK your mobile will be charged 5/month Please confirm by replying YES or NO. If you reply NO you will not be charged"
            rec["label"] = Label.NON_SCAM.value
            rec["scam_category"] = ScamCategory.NONE.value
            rec["tactics"] = ["payment_request"]
            rec["evidence_spans"] = [
                {"tactic": "payment_request", "evidence": "mobile will be charged"}
            ]
            rec["requested_action"] = RequestedAction.REPLY.value
            rec["target_asset"] = TargetAsset.MONEY.value
            rec["urgency_level"] = UrgencyLevel.NONE.value
            rec["impersonated_entity"] = ImpersonatedEntity.COMPANY.value
            rec["label_confidence"] = LabelConfidence.MEDIUM.value
            rec["known_unknown_status"] = KnownUnknownStatus.KNOWN.value
            rec["notes"] = "Commercial spam boundary: explicit opt-in confirmation with clear cancellation choice ('reply NO'). Non-scam marketing."

        elif sid == "uci_sms_0096":
            # "Your free ringtone is waiting to be collected. Simply text the password \"MIX\" to 85069 to verify. Get Usher and Britney. FML, PO Box 5249, MK17 92H. 450Ppw 16"
            rec["label"] = Label.SCAM.value
            rec["scam_category"] = ScamCategory.SHOPPING.value
            rec["tactics"] = ["reward_claim", "payment_request", "verification_request"]
            rec["evidence_spans"] = [
                {"tactic": "reward_claim", "evidence": "free ringtone is waiting"},
                {"tactic": "verification_request", "evidence": "verify"},
                {"tactic": "payment_request", "evidence": "450Ppw"},
            ]
            rec["requested_action"] = RequestedAction.REPLY.value
            rec["target_asset"] = TargetAsset.MONEY.value
            rec["urgency_level"] = UrgencyLevel.LOW.value
            rec["impersonated_entity"] = ImpersonatedEntity.COMPANY.value
            rec["label_confidence"] = LabelConfidence.HIGH.value
            rec["known_unknown_status"] = KnownUnknownStatus.KNOWN.value
            rec["notes"] = "Commercial scam: lures user with 'free' while secretly enrolling them in a 450p/week subscription."

        elif sid == "uci_sms_0140":
            # "You'll not rcv any more msgs from the chat svc. For FREE Hardcore services text GO to: 69988 If u get nothing u must Age Verify with yr network & try again"
            rec["label"] = Label.NON_SCAM.value
            rec["scam_category"] = ScamCategory.NONE.value
            rec["tactics"] = ["verification_request"]
            rec["evidence_spans"] = [
                {"tactic": "verification_request", "evidence": "Age Verify with yr network"}
            ]
            rec["requested_action"] = RequestedAction.REPLY.value
            rec["target_asset"] = TargetAsset.NONE.value
            rec["urgency_level"] = UrgencyLevel.NONE.value
            rec["impersonated_entity"] = ImpersonatedEntity.NONE.value
            rec["label_confidence"] = LabelConfidence.MEDIUM.value
            rec["known_unknown_status"] = KnownUnknownStatus.KNOWN.value
            rec["notes"] = "Adult commercial chat service opt-out notice with age check instruction. Unsolicited marketing, but not financial fraud."

        elif sid == "uci_sms_0148":
            # "FreeMsg Why haven't you replied to my text? I'm Randy, sexy, female and live local. Luv to hear from u. Netcollex Ltd 08700621170150p per msg reply Stop to end"
            rec["label"] = Label.SCAM.value
            rec["scam_category"] = ScamCategory.ROMANCE.value
            rec["tactics"] = ["romance_manipulation", "payment_request"]
            rec["evidence_spans"] = [
                {"tactic": "romance_manipulation", "evidence": "Why haven't you replied to my text?"},
                {"tactic": "payment_request", "evidence": "150p per msg"},
            ]
            rec["requested_action"] = RequestedAction.REPLY.value
            rec["target_asset"] = TargetAsset.MONEY.value
            rec["urgency_level"] = UrgencyLevel.LOW.value
            rec["impersonated_entity"] = ImpersonatedEntity.NONE.value
            rec["label_confidence"] = LabelConfidence.HIGH.value
            rec["known_unknown_status"] = KnownUnknownStatus.KNOWN.value
            rec["notes"] = "Deceptive dating chat solicitation tricking recipient into expensive 150p/msg replies."

        elif sid == "uci_sms_0166":
            # "BangBabes Ur order is on the way. U SHOULD receive a Service Msg 2 download UR content. If U do not, GoTo wap. bangb. tv on UR mobile internet/service menu"
            rec["label"] = Label.SCAM.value
            rec["scam_category"] = ScamCategory.SHOPPING.value
            rec["tactics"] = ["impersonation", "link_redirection"]
            rec["evidence_spans"] = [
                {"tactic": "impersonation", "evidence": "BangBabes"},
                {"tactic": "link_redirection", "evidence": "GoTo wap. bangb. tv"},
            ]
            rec["requested_action"] = RequestedAction.CLICK_LINK.value
            rec["target_asset"] = TargetAsset.MONEY.value
            rec["urgency_level"] = UrgencyLevel.LOW.value
            rec["impersonated_entity"] = ImpersonatedEntity.COMPANY.value
            rec["label_confidence"] = LabelConfidence.MEDIUM.value
            rec["known_unknown_status"] = KnownUnknownStatus.KNOWN.value
            rec["notes"] = "Deceptive order delivery pretext driving traffic to adult WAP download site."

        # -------------------------------------------------------------
        # 7. Ambiguous / Terse Messages (5 samples)
        # -------------------------------------------------------------
        elif sid == "uci_sms_0044":
            # "WHO ARE YOU SEEING?"
            rec["label"] = Label.NON_SCAM.value
            rec["scam_category"] = ScamCategory.NONE.value
            rec["tactics"] = []
            rec["evidence_spans"] = []
            rec["requested_action"] = RequestedAction.REPLY.value
            rec["target_asset"] = TargetAsset.NONE.value
            rec["urgency_level"] = UrgencyLevel.NONE.value
            rec["impersonated_entity"] = ImpersonatedEntity.NONE.value
            rec["label_confidence"] = LabelConfidence.LOW.value
            rec["known_unknown_status"] = KnownUnknownStatus.UNKNOWN.value
            rec["notes"] = "Ambiguous case: terse interrogative message with zero context. Low confidence non_scam."

        elif sid == "uci_sms_0435":
            # "Booked ticket for pongal?"
            rec["label"] = Label.NON_SCAM.value
            rec["scam_category"] = ScamCategory.NONE.value
            rec["tactics"] = []
            rec["evidence_spans"] = []
            rec["requested_action"] = RequestedAction.REPLY.value
            rec["target_asset"] = TargetAsset.NONE.value
            rec["urgency_level"] = UrgencyLevel.NONE.value
            rec["impersonated_entity"] = ImpersonatedEntity.NONE.value
            rec["label_confidence"] = LabelConfidence.HIGH.value
            rec["known_unknown_status"] = KnownUnknownStatus.KNOWN.value
            rec["notes"] = "Culturally specific Indian festival travel inquiry. Clearly non_scam."

        elif sid == "uci_sms_0452":
            # "hanks lotsly!"
            rec["label"] = Label.NON_SCAM.value
            rec["scam_category"] = ScamCategory.NONE.value
            rec["tactics"] = []
            rec["evidence_spans"] = []
            rec["requested_action"] = RequestedAction.NONE.value
            rec["target_asset"] = TargetAsset.NONE.value
            rec["urgency_level"] = UrgencyLevel.NONE.value
            rec["impersonated_entity"] = ImpersonatedEntity.NONE.value
            rec["label_confidence"] = LabelConfidence.HIGH.value
            rec["known_unknown_status"] = KnownUnknownStatus.KNOWN.value
            rec["notes"] = "Informal friendly expression of gratitude. Benign non_scam."

        elif sid == "uci_sms_0479":
            # "Tension ah?what machi?any problem?"
            rec["label"] = Label.NON_SCAM.value
            rec["scam_category"] = ScamCategory.NONE.value
            rec["tactics"] = []
            rec["evidence_spans"] = []
            rec["requested_action"] = RequestedAction.REPLY.value
            rec["target_asset"] = TargetAsset.NONE.value
            rec["urgency_level"] = UrgencyLevel.NONE.value
            rec["impersonated_entity"] = ImpersonatedEntity.NONE.value
            rec["label_confidence"] = LabelConfidence.HIGH.value
            rec["known_unknown_status"] = KnownUnknownStatus.KNOWN.value
            rec["notes"] = "Tamil/Indian colloquial inquiry ('machi' = friend) checking on welfare. Non-scam."

        elif sid == "uci_sms_0497":
            # "Got meh... When?"
            rec["label"] = Label.NON_SCAM.value
            rec["scam_category"] = ScamCategory.NONE.value
            rec["tactics"] = []
            rec["evidence_spans"] = []
            rec["requested_action"] = RequestedAction.REPLY.value
            rec["target_asset"] = TargetAsset.NONE.value
            rec["urgency_level"] = UrgencyLevel.NONE.value
            rec["impersonated_entity"] = ImpersonatedEntity.NONE.value
            rec["label_confidence"] = LabelConfidence.LOW.value
            rec["known_unknown_status"] = KnownUnknownStatus.UNKNOWN.value
            rec["notes"] = "Ambiguous case: Singlish colloquial snippet with insufficient context to confirm intent."

        annotated.append(rec)

    return annotated


def write_and_validate_pilot_dataset() -> Path:
    """Generates and validates the pilot dataset file."""
    root = Path(__file__).resolve().parents[2]
    out_path = root / "data" / "evaluation" / "annotation_pilot" / "pilot_dataset.jsonl"
    annotated_records = create_annotated_pilot()

    validator = DatasetValidator()
    val_res = validator.validate_dataset(annotated_records)

    if not val_res.is_valid:
        raise ValueError(f"Pilot dataset validation failed:\n{val_res.summary()}")

    with open(out_path, "w", encoding="utf-8") as f:
        for r in annotated_records:
            f.write(json.dumps(r, ensure_ascii=False) + "\n")

    return out_path


if __name__ == "__main__":
    p = write_and_validate_pilot_dataset()
    print(f"Successfully generated and validated pilot dataset with 60 records at: {p}")
