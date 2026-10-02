"""Synthetic visual dataset generator for ScamShield AI Phase 9B.

Generates a controlled benchmark corpus of screenshots and layout graphics
representing:
- Group A: Legitimate communications (delivery stepper, bank statement table, promo flyer, chat).
- Group B: Common visual scam templates (modal lockout, lottery coupon, KYC form, QR refund phish).
- Group C: Hard Negatives (legitimate POS receipt QR, OTP keypad screen, security shield alert, credit card).
- Paired Variants: Matched layout templates with divergent text (scam vs. benign)
  and matched scam text with divergent visual presentation (styled vs. plain).

GUARANTEES:
- 100% Deterministic & Offline: Uses Pillow drawing primitives and default fonts.
- Genuinely distinct layout archetypes to guarantee zero cross-split perceptual overlap (dHash).
- Produces dataset manifest adhering to `VisualSampleRecord` schema.
"""

import json
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple
import numpy as np
from PIL import Image, ImageDraw, ImageFont

from .leakage import compute_dhash, compute_image_sha256
from .schemas import VisualSampleRecord


def _draw_qr_code_pattern(
    draw: ImageDraw.ImageDraw, top_left: Tuple[int, int], size: int = 120, cell_size: int = 8
) -> None:
    """Draws a deterministic pseudo-QR grid pattern with positioning squares."""
    x0, y0 = top_left
    draw.rectangle([x0, y0, x0 + size, y0 + size], fill=(255, 255, 255), outline=(0, 0, 0), width=2)

    corners = [(x0 + 8, y0 + 8), (x0 + size - 36, y0 + 8), (x0 + 8, y0 + size - 36)]
    for cx, cy in corners:
        draw.rectangle([cx, cy, cx + 28, cy + 28], fill=(0, 0, 0))
        draw.rectangle([cx + 6, cy + 6, cx + 22, cy + 22], fill=(255, 255, 255))
        draw.rectangle([cx + 10, cy + 10, cx + 18, cy + 18], fill=(0, 0, 0))

    rng = np.random.RandomState(42)
    grid_cells = size // cell_size
    for i in range(2, grid_cells - 2):
        for j in range(2, grid_cells - 2):
            if (i < 5 and j < 5) or (i >= grid_cells - 5 and j < 5) or (i < 5 and j >= grid_cells - 5):
                continue
            if rng.rand() > 0.45:
                px = x0 + i * cell_size
                py = y0 + j * cell_size
                draw.rectangle([px, py, px + cell_size - 1, py + cell_size - 1], fill=(0, 0, 0))


# =========================================================================
# Archetype 1: Delivery Stepper (Group A - Delivery)
# =========================================================================
def render_delivery_stepper(output_path: Path, title: str, lines: List[str], btn_text: str = "TRACK") -> None:
    w, h = 420, 460
    img = Image.new("RGB", (w, h), color=(250, 252, 255))
    draw = ImageDraw.ImageDraw(img)
    font = ImageFont.load_default()

    # Blue top bar
    draw.rectangle([0, 0, w, 55], fill=(41, 128, 185))
    draw.text((20, 20), title, fill=(255, 255, 255), font=font)

    # Horizontal stepper track in upper third
    draw.line([60, 110, 360, 110], fill=(189, 195, 199), width=4)
    draw.line([60, 110, 210, 110], fill=(46, 204, 113), width=4)
    # Step circles
    steps = [(60, 110, "Order", (46, 204, 113)), (210, 110, "In Transit", (46, 204, 113)), (360, 110, "Delivered", (189, 195, 199))]
    for sx, sy, sname, col in steps:
        draw.ellipse([sx - 14, sy - 14, sx + 14, sy + 14], fill=col)
        draw.text((sx - 18, sy + 20), sname, fill=(80, 80, 80), font=font)

    # Content card in middle
    draw.rectangle([25, 175, w - 25, 360], fill=(255, 255, 255), outline=(220, 225, 230), width=1)
    cy = 195
    for line in lines:
        draw.text((45, cy), line, fill=(50, 50, 50), font=font)
        cy += 24

    # Button
    draw.rectangle([40, 390, w - 40, 434], fill=(41, 128, 185))
    draw.text((170, 404), btn_text, fill=(255, 255, 255), font=font)

    img.save(output_path, format="PNG")


# =========================================================================
# Archetype 2: Bank Statement Table (Group A - Statement)
# =========================================================================
def render_bank_statement_table(output_path: Path, title: str, lines: List[str]) -> None:
    w, h = 450, 420
    img = Image.new("RGB", (w, h), color=(255, 255, 255))
    draw = ImageDraw.ImageDraw(img)
    font = ImageFont.load_default()

    # Navy top banner
    draw.rectangle([0, 0, w, 50], fill=(0, 45, 98))
    draw.text((20, 18), title, fill=(255, 255, 255), font=font)

    # Notice text
    y = 65
    for l in lines[:2]:
        draw.text((25, y), l, fill=(60, 60, 60), font=font)
        y += 20

    # Table with alternating rows
    table_top = y + 10
    draw.rectangle([20, table_top, w - 20, table_top + 26], fill=(230, 235, 245))
    draw.text((30, table_top + 6), "DATE        DESCRIPTION               AMOUNT (INR)", fill=(0, 45, 98), font=font)

    row_data = [
        ("02-Aug-26", "SALARY CREDIT - TECH CORP", "+75,000.00", (255, 255, 255)),
        ("08-Aug-26", "SUPERMARKET RETAIL PURCHASE", "-3,450.00", (245, 248, 252)),
        ("15-Aug-26", "ELECTRICITY BILL PAYMENT", "-1,240.00", (255, 255, 255)),
        ("22-Aug-26", "ATM CASH WITHDRAWAL", "-5,000.00", (245, 248, 252)),
        ("31-Aug-26", "MONTHLY INTEREST CREDITED", "+320.00", (255, 255, 255)),
    ]
    ry = table_top + 28
    for dt, desc, amt, bg in row_data:
        draw.rectangle([20, ry, w - 20, ry + 24], fill=bg)
        draw.text((30, ry + 5), f"{dt}  {desc:<25} {amt:>10}", fill=(40, 40, 40), font=font)
        ry += 26

    draw.text((25, ry + 20), "Official NetBanking: netbanking.bank.com", fill=(100, 100, 100), font=font)
    img.save(output_path, format="PNG")


# =========================================================================
# Archetype 3: Wide Promo Flyer (Group A - Promo)
# =========================================================================
def render_promo_flyer(output_path: Path, title: str, lines: List[str], discount: str = "25% OFF") -> None:
    w, h = 500, 320
    img = Image.new("RGB", (w, h), color=(253, 248, 255))
    draw = ImageDraw.ImageDraw(img)
    font = ImageFont.load_default()

    # Left colored vertical splash column
    draw.rectangle([0, 0, 160, h], fill=(142, 68, 173))
    # Discount badge in left column
    draw.ellipse([25, 70, 135, 180], fill=(241, 196, 15))
    draw.text((45, 115), discount, fill=(0, 0, 0), font=font)
    draw.text((35, 210), "FESTIVE SALE", fill=(255, 255, 255), font=font)

    # Right side text
    draw.text((185, 30), title, fill=(142, 68, 173), font=font)
    draw.line([185, 55, w - 25, 55], fill=(220, 200, 230), width=1)

    cy = 75
    for l in lines:
        draw.text((185, cy), l, fill=(50, 50, 50), font=font)
        cy += 24

    # Shop button on right
    draw.rectangle([185, 240, 360, 285], fill=(155, 89, 182))
    draw.text((230, 255), "SHOP NOW", fill=(255, 255, 255), font=font)

    img.save(output_path, format="PNG")


# =========================================================================
# Archetype 4: Chat Messenger (Group A - Chat)
# =========================================================================
def render_chat_messenger(output_path: Path, title: str, messages: List[Tuple[str, str, bool]]) -> None:
    w, h = 360, 520
    # WhatsApp beige background
    img = Image.new("RGB", (w, h), color=(236, 229, 221))
    draw = ImageDraw.ImageDraw(img)
    font = ImageFont.load_default()

    # Dark green WhatsApp header
    draw.rectangle([0, 0, w, 55], fill=(7, 94, 84))
    draw.ellipse([15, 12, 45, 42], fill=(18, 140, 126))
    draw.text((55, 20), title, fill=(255, 255, 255), font=font)

    # Chat bubbles
    cy = 80
    for sender, msg, is_user in messages:
        if is_user:
            # Right-aligned green bubble
            bx0 = 100
            bx1 = w - 20
            draw.rectangle([bx0, cy, bx1, cy + 42], fill=(220, 248, 198), outline=(200, 230, 180))
            draw.text((bx0 + 10, cy + 6), f"{sender}:", fill=(7, 94, 84), font=font)
            draw.text((bx0 + 10, cy + 22), msg, fill=(20, 20, 20), font=font)
        else:
            # Left-aligned white bubble
            bx0 = 20
            bx1 = 280
            draw.rectangle([bx0, cy, bx1, cy + 42], fill=(255, 255, 255), outline=(225, 225, 225))
            draw.text((bx0 + 10, cy + 6), f"{sender}:", fill=(52, 73, 94), font=font)
            draw.text((bx0 + 10, cy + 22), msg, fill=(20, 20, 20), font=font)
        cy += 58

    # Input bar at bottom
    draw.rectangle([15, h - 50, w - 60, h - 15], fill=(255, 255, 255))
    draw.text((25, h - 38), "Type a message...", fill=(150, 150, 150), font=font)
    draw.ellipse([w - 50, h - 50, w - 15, h - 15], fill=(7, 94, 84))

    img.save(output_path, format="PNG")


# =========================================================================
# Archetype 5: Modal Lockout Popup (Group B - Account Lock)
# =========================================================================
def render_modal_lockout(output_path: Path, title: str, lines: List[str]) -> None:
    w, h = 440, 440
    # Dimmed background overlay
    img = Image.new("RGB", (w, h), color=(100, 105, 115))
    draw = ImageDraw.ImageDraw(img)
    font = ImageFont.load_default()

    # White modal in center
    mx0, my0, mx1, my1 = 40, 45, w - 40, h - 45
    draw.rectangle([mx0, my0, mx1, my1], fill=(255, 255, 255), outline=(200, 50, 50), width=2)

    # Red warning header in modal
    draw.rectangle([mx0, my0, mx1, my0 + 50], fill=(200, 35, 51))
    draw.text((mx0 + 20, my0 + 18), title, fill=(255, 255, 255), font=font)

    # Warning triangle
    draw.polygon([(w // 2, my0 + 65), (w // 2 - 25, my0 + 105), (w // 2 + 25, my0 + 105)], fill=(231, 76, 60))
    draw.text((w // 2 - 3, my0 + 82), "!", fill=(255, 255, 255), font=font)

    # Body lines
    cy = my0 + 120
    for l in lines:
        draw.text((mx0 + 25, cy), l, fill=(30, 30, 30), font=font)
        cy += 22

    # High-urgency button
    draw.rectangle([mx0 + 35, my1 - 60, mx1 - 35, my1 - 20], fill=(200, 35, 51))
    draw.text((mx0 + 80, my1 - 45), "VERIFY CREDENTIALS NOW", fill=(255, 255, 255), font=font)

    img.save(output_path, format="PNG")


# =========================================================================
# Archetype 6: Lottery Coupon Voucher (Group B - Lottery)
# =========================================================================
def render_lottery_coupon(output_path: Path, title: str, lines: List[str], amount: str = "RS. 25 LAKHS") -> None:
    w, h = 460, 380
    img = Image.new("RGB", (w, h), color=(255, 248, 230))
    draw = ImageDraw.ImageDraw(img)
    font = ImageFont.load_default()

    # Dashed/ornate outer gold border
    draw.rectangle([15, 15, w - 15, h - 15], outline=(218, 165, 32), width=3)
    draw.rectangle([22, 22, w - 22, h - 22], outline=(243, 156, 18), width=1)

    # Top banner
    draw.rectangle([25, 25, w - 25, 75], fill=(243, 156, 18))
    draw.text((50, 42), title, fill=(255, 255, 255), font=font)

    # Prize seal circle on right
    draw.ellipse([w - 120, 95, w - 40, 175], fill=(230, 126, 34))
    draw.text((w - 110, 130), "WINNER!", fill=(255, 255, 255), font=font)

    # Amount box
    draw.rectangle([35, 95, w - 140, 145], fill=(255, 255, 255), outline=(218, 165, 32))
    draw.text((50, 112), f"PRIZE VALUE: {amount}", fill=(180, 50, 20), font=font)

    # Text details
    cy = 160
    for l in lines:
        draw.text((35, cy), l, fill=(40, 40, 40), font=font)
        cy += 22

    # Claim button
    draw.rectangle([50, h - 65, w - 50, h - 28], fill=(211, 84, 0))
    draw.text((150, h - 52), "CLAIM YOUR PRIZE NOW", fill=(255, 255, 255), font=font)

    img.save(output_path, format="PNG")


# =========================================================================
# Archetype 7: Split KYC Form (Group B - KYC Renewal)
# =========================================================================
def render_kyc_split_form(output_path: Path, title: str, lines: List[str]) -> None:
    w, h = 430, 470
    img = Image.new("RGB", (w, h), color=(252, 250, 255))
    draw = ImageDraw.ImageDraw(img)
    font = ImageFont.load_default()

    # Left colored stripe (40px)
    draw.rectangle([0, 0, 40, h], fill=(142, 68, 173))

    # Top alert ribbon
    draw.rectangle([40, 0, w, 60], fill=(245, 235, 255))
    draw.text((60, 22), title, fill=(142, 68, 173), font=font)

    cy = 75
    for l in lines:
        draw.text((60, cy), l, fill=(40, 40, 40), font=font)
        cy += 20

    # Form fields (fake input boxes)
    cy += 10
    fields = ["Aadhaar Number (12 Digits):", "PAN Card Number:", "Registered Mobile OTP:"]
    for f in fields:
        draw.text((60, cy), f, fill=(70, 70, 70), font=font)
        cy += 18
        draw.rectangle([60, cy, w - 40, cy + 28], fill=(255, 255, 255), outline=(180, 180, 180))
        cy += 36

    # Submit button
    draw.rectangle([60, cy + 10, w - 40, cy + 50], fill=(142, 68, 173))
    draw.text((140, cy + 24), "SUBMIT KYC VERIFICATION", fill=(255, 255, 255), font=font)

    img.save(output_path, format="PNG")


# =========================================================================
# Archetype 8: Big QR Phish Screen (Group B - QR Phish)
# =========================================================================
def render_qr_phish_screen(output_path: Path, title: str, lines: List[str]) -> None:
    w, h = 390, 490
    img = Image.new("RGB", (w, h), color=(245, 250, 255))
    draw = ImageDraw.ImageDraw(img)
    font = ImageFont.load_default()

    # Top blue bar
    draw.rectangle([0, 0, w, 55], fill=(41, 128, 185))
    draw.text((20, 20), title, fill=(255, 255, 255), font=font)

    cy = 70
    for l in lines:
        draw.text((25, cy), l, fill=(40, 40, 40), font=font)
        cy += 20

    # Prominent QR pattern in middle
    qr_size = 140
    qr_x = (w - qr_size) // 2
    _draw_qr_code_pattern(draw, (qr_x, cy + 10), size=qr_size, cell_size=9)

    cy += qr_size + 25
    draw.text((qr_x - 10, cy), "Scan to receive payment instantly", fill=(192, 57, 43), font=font)

    # Button
    draw.rectangle([35, h - 55, w - 35, h - 15], fill=(41, 128, 185))
    draw.text((105, h - 40), "CONFIRM QR SCAN IN UPI APP", fill=(255, 255, 255), font=font)

    img.save(output_path, format="PNG")


# =========================================================================
# Archetype 9: Retail POS Receipt with QR (Group C - Hard Neg QR)
# =========================================================================
def render_pos_receipt_qr(output_path: Path, title: str, lines: List[str]) -> None:
    w, h = 430, 480
    # Gray background, white paper receipt in center
    img = Image.new("RGB", (w, h), color=(230, 232, 235))
    draw = ImageDraw.ImageDraw(img)
    font = ImageFont.load_default()

    rx0, ry0, rx1, ry1 = 30, 20, w - 30, h - 20
    draw.rectangle([rx0, ry0, rx1, ry1], fill=(255, 255, 255), outline=(200, 200, 200))

    # Jagged / dashed receipt header line
    draw.text((rx0 + 20, ry0 + 15), title, fill=(0, 0, 0), font=font)
    draw.line([rx0 + 20, ry0 + 38, rx1 - 20, ry0 + 38], fill=(150, 150, 150), width=1)

    cy = ry0 + 48
    for l in lines:
        draw.text((rx0 + 20, cy), l, fill=(40, 40, 40), font=font)
        cy += 22

    # QR Code in bottom-right quadrant of receipt
    qr_size = 110
    _draw_qr_code_pattern(draw, (rx1 - qr_size - 20, cy + 10), size=qr_size, cell_size=7)

    # Left of QR: Total Due summary
    draw.rectangle([rx0 + 20, cy + 15, rx1 - qr_size - 35, cy + 95], fill=(245, 245, 245))
    draw.text((rx0 + 30, cy + 30), "AMOUNT DUE:", fill=(100, 100, 100), font=font)
    draw.text((rx0 + 30, cy + 55), "INR 1,480.00", fill=(0, 128, 0), font=font)

    draw.text((rx0 + 20, ry1 - 30), "*** THANK YOU FOR SHOPPING ***", fill=(120, 120, 120), font=font)
    img.save(output_path, format="PNG")


# =========================================================================
# Archetype 10: OTP Keypad Dialog (Group C - Hard Neg OTP)
# =========================================================================
def render_otp_keypad_dialog(output_path: Path, title: str, lines: List[str]) -> None:
    w, h = 410, 490
    img = Image.new("RGB", (w, h), color=(250, 250, 252))
    draw = ImageDraw.ImageDraw(img)
    font = ImageFont.load_default()

    # Dark blue clean header
    draw.rectangle([0, 0, w, 50], fill=(24, 43, 73))
    draw.text((25, 18), title, fill=(255, 255, 255), font=font)

    cy = 70
    for l in lines:
        draw.text((25, cy), l, fill=(45, 45, 45), font=font)
        cy += 20

    # 6 square OTP entry boxes centered horizontally
    cy += 15
    box_w = 40
    gap = 12
    start_x = (w - (6 * box_w + 5 * gap)) // 2
    for i in range(6):
        bx = start_x + i * (box_w + gap)
        draw.rectangle([bx, cy, bx + box_w, cy + 44], fill=(255, 255, 255), outline=(70, 130, 180), width=2)
        # Put dot inside first 4 boxes
        if i < 4:
            draw.ellipse([bx + 16, cy + 18, bx + 24, cy + 26], fill=(0, 0, 0))

    cy += 65
    draw.text((start_x, cy), "Do not share OTP with anyone.", fill=(180, 50, 50), font=font)

    # Green submit button
    draw.rectangle([40, h - 60, w - 40, h - 18], fill=(39, 174, 96))
    draw.text((150, h - 44), "SUBMIT SECURE OTP", fill=(255, 255, 255), font=font)

    img.save(output_path, format="PNG")


# =========================================================================
# Archetype 11: Security Shield Alert (Group C - Hard Neg Alert)
# =========================================================================
def render_security_shield_alert(output_path: Path, title: str, lines: List[str]) -> None:
    w, h = 440, 440
    img = Image.new("RGB", (w, h), color=(255, 245, 248))
    draw = ImageDraw.ImageDraw(img)
    font = ImageFont.load_default()

    # Burgundy header
    draw.rectangle([0, 0, w, 55], fill=(153, 0, 51))
    draw.text((20, 20), title, fill=(255, 255, 255), font=font)

    # Top-center shield shape
    draw.polygon([(w // 2, 80), (w // 2 + 35, 95), (w // 2 + 25, 145), (w // 2, 165), (w // 2 - 25, 145), (w // 2 - 35, 95)], fill=(153, 0, 51))
    draw.text((w // 2 - 4, 115), "S", fill=(255, 255, 255), font=font)

    cy = 185
    for l in lines:
        draw.text((25, cy), l, fill=(40, 40, 40), font=font)
        cy += 20

    # Dual buttons side by side at bottom
    btn_w = 175
    btn_h = 40
    by = h - 60
    # Left primary red button
    draw.rectangle([30, by, 30 + btn_w, by + btn_h], fill=(153, 0, 51))
    draw.text((50, by + 14), "FREEZE CARD IN APP", fill=(255, 255, 255), font=font)
    # Right secondary neutral gray button
    draw.rectangle([w - 30 - btn_w, by, w - 30, by + btn_h], fill=(108, 117, 125))
    draw.text((w - 30 - btn_w + 35, by + 14), "I RECOGNIZE THIS", fill=(255, 255, 255), font=font)

    img.save(output_path, format="PNG")


# =========================================================================
# Archetype 12: Credit Card Billing (Group C - Hard Neg Card)
# =========================================================================
def render_credit_card_billing(output_path: Path, title: str, lines: List[str]) -> None:
    w, h = 460, 400
    img = Image.new("RGB", (w, h), color=(245, 248, 252))
    draw = ImageDraw.ImageDraw(img)
    font = ImageFont.load_default()

    draw.text((25, 20), title, fill=(0, 80, 160), font=font)

    # Credit card mockup in center (380x180)
    cx0, cy0, cx1, cy1 = 40, 50, w - 40, 220
    draw.rectangle([cx0, cy0, cx1, cy1], fill=(26, 82, 118))
    # EMV chip on left
    draw.rectangle([cx0 + 25, cy0 + 35, cx0 + 65, cy0 + 70], fill=(212, 175, 55))
    # Card number dots
    draw.text((cx0 + 25, cy0 + 95), "****  ****  ****  6712", fill=(255, 255, 255), font=font)
    draw.text((cx0 + 25, cy0 + 130), "VAL THRU: 08/29", fill=(200, 220, 240), font=font)
    draw.text((cx1 - 90, cy0 + 130), "VISA PLATINUM", fill=(255, 255, 255), font=font)

    # Billing info below card
    cy = 240
    for l in lines:
        draw.text((40, cy), l, fill=(40, 40, 40), font=font)
        cy += 20

    # Pay button
    draw.rectangle([40, h - 50, w - 40, h - 15], fill=(0, 80, 160))
    draw.text((150, h - 38), "PAY VIA OFFICIAL APP", fill=(255, 255, 255), font=font)

    img.save(output_path, format="PNG")


# =========================================================================
# Archetype 13: Standard Alert Card (Paired Layout Template T_ALERT)
# =========================================================================
def render_standard_alert_card(
    output_path: Path, title: str, lines: List[str], btn_text: str = "CONFIRM NOW"
) -> None:
    w, h = 400, 480
    img = Image.new("RGB", (w, h), color=(254, 249, 248))
    draw = ImageDraw.ImageDraw(img)
    font = ImageFont.load_default()

    draw.rectangle([0, 0, w, 65], fill=(169, 50, 38))
    draw.text((20, 24), title, fill=(255, 255, 255), font=font)

    # Accent badge
    draw.rectangle([25, 80, 180, 104], fill=(255, 193, 7))
    draw.text((33, 86), "ACTION REQUIRED", fill=(0, 0, 0), font=font)

    cy = 125
    for l in lines:
        draw.text((25, cy), l, fill=(40, 40, 40), font=font)
        cy += 22

    draw.rectangle([35, h - 60, w - 35, h - 18], fill=(169, 50, 38))
    draw.text((140, h - 44), btn_text, fill=(255, 255, 255), font=font)

    img.save(output_path, format="PNG")


# =========================================================================
# Archetype 14: Plain Text Note (Paired Text Template - Plain)
# =========================================================================
def render_plain_text_note(output_path: Path, title: str, lines: List[str]) -> None:
    w, h = 380, 420
    img = Image.new("RGB", (w, h), color=(255, 255, 255))
    draw = ImageDraw.ImageDraw(img)
    font = ImageFont.load_default()

    # Ruled notebook lines
    for ry in range(40, h, 28):
        draw.line([15, ry, w - 15, ry], fill=(240, 240, 240), width=1)

    draw.text((25, 20), title, fill=(120, 120, 120), font=font)

    cy = 60
    for l in lines:
        draw.text((25, cy), l, fill=(30, 30, 30), font=font)
        cy += 28

    img.save(output_path, format="PNG")


# =========================================================================
# Archetype 15: Urgent Compromise Card (Paired Text Template - Styled)
# =========================================================================
def render_urgent_compromise_card(output_path: Path, title: str, lines: List[str]) -> None:
    w, h = 420, 420
    img = Image.new("RGB", (w, h), color=(255, 240, 240))
    draw = ImageDraw.ImageDraw(img)
    font = ImageFont.load_default()

    # Red border
    draw.rectangle([10, 10, w - 10, h - 10], outline=(203, 67, 53), width=3)
    # Center alert icon
    draw.rectangle([w // 2 - 25, 30, w // 2 + 25, 65], fill=(203, 67, 53))
    draw.text((w // 2 - 14, 42), "LOCK", fill=(255, 255, 255), font=font)
    draw.text((30, 85), title, fill=(180, 40, 30), font=font)

    cy = 120
    for l in lines:
        draw.text((30, cy), l, fill=(40, 40, 40), font=font)
        cy += 24

    draw.rectangle([35, h - 65, w - 35, h - 25], fill=(203, 67, 53))
    draw.text((130, h - 48), "UNLOCK BANK ACCESS", fill=(255, 255, 255), font=font)
    img.save(output_path, format="PNG")



def build_synthetic_dataset(output_dir: Path) -> Tuple[List[VisualSampleRecord], Path]:
    """Generates the full benchmark dataset with distinct UI archetypes across Groups A, B, C and pairs."""
    images_dir = output_dir / "synthetic"
    meta_dir = output_dir / "metadata"
    images_dir.mkdir(parents=True, exist_ok=True)
    meta_dir.mkdir(parents=True, exist_ok=True)

    records: List[VisualSampleRecord] = []

    specs: List[Dict[str, Any]] = [
        # GROUP A: Legitimate Communications
        {
            "id": "legit_delivery_01",
            "scenario": "delivery_notice",
            "label": "non_scam",
            "group": "group_a_delivery",
            "render_fn": render_delivery_stepper,
            "title": "FastTrack Logistics - Shipment",
            "body": [
                "Package #TRK-98214 is out for delivery.",
                "Expected window: 2:00 PM - 5:00 PM.",
                "Driver: Rajesh K. No OTP required.",
                "Thank you for shopping with us.",
            ],
            "notes": "Legitimate logistics stepper interface.",
        },
        {
            "id": "legit_delivery_02",
            "scenario": "delivery_notice",
            "label": "non_scam",
            "group": "group_a_delivery",
            "render_fn": render_delivery_stepper,
            "title": "BlueDart Express Courier Update",
            "body": [
                "Airway Bill #BD-44102 in transit.",
                "Hub: Bengaluru Central Sorting Facility.",
                "Courier delivery agent assigned.",
            ],
            "notes": "Legitimate logistics stepper interface variant.",
        },
        {
            "id": "legit_statement_01",
            "scenario": "bank_statement",
            "label": "non_scam",
            "group": "group_a_statement",
            "render_fn": render_bank_statement_table,
            "title": "HDFC Bank - e-Statement Ready",
            "body": [
                "Statement for account **4821 is generated.",
                "Period: Aug 01 - Aug 31, 2026.",
            ],
            "notes": "Legitimate banking statement with transaction table.",
        },
        {
            "id": "legit_statement_02",
            "scenario": "bank_statement",
            "label": "non_scam",
            "group": "group_a_statement",
            "render_fn": render_bank_statement_table,
            "title": "Axis Bank Monthly Account Summary",
            "body": [
                "Summary for Savings A/C **9910.",
                "Closing Balance: Rs. 65,400.00.",
            ],
            "notes": "Banking tabular statement variant.",
        },
        {
            "id": "legit_promo_01",
            "scenario": "retail_promo",
            "label": "non_scam",
            "group": "group_a_promo",
            "render_fn": render_promo_flyer,
            "title": "Weekend Mega Sale - FabIndia",
            "body": [
                "Enjoy flat 25% off on ethnic wear.",
                "Valid Friday to Sunday in all stores.",
                "Use promo code: FESTIVE25 at checkout.",
                "Visit www.fabindia.com/festive",
            ],
            "notes": "Retail promo flyer with left splash badge.",
        },
        {
            "id": "legit_promo_02",
            "scenario": "retail_promo",
            "label": "non_scam",
            "group": "group_a_promo",
            "render_fn": render_promo_flyer,
            "title": "Autumn Linen Season Launch",
            "body": [
                "Explore the new handloom collection.",
                "Double reward points for members.",
                "Free shipping on orders above Rs. 999.",
            ],
            "notes": "Retail flyer variant with orange theme.",
        },
        {
            "id": "legit_chat_01",
            "scenario": "chat_message",
            "label": "non_scam",
            "group": "group_a_chat",
            "render_fn": render_chat_messenger,
            "title": "Priya Sharma",
            "chat_messages": [
                ("Priya", "Hey! Are we meeting for lunch at 1?", False),
                ("You", "Yes, table booked under my name.", True),
                ("Priya", "Great, see you there!", False),
            ],
            "notes": "Personal chat conversation layout.",
        },
        {
            "id": "legit_chat_02",
            "scenario": "chat_message",
            "label": "non_scam",
            "group": "group_a_chat",
            "render_fn": render_chat_messenger,
            "title": "Family Group",
            "chat_messages": [
                ("Mom", "Did you reach office safely?", False),
                ("You", "Yes Mom, just reached desk.", True),
                ("Mom", "Remember to drink water today.", False),
            ],
            "notes": "Family chat conversation layout.",
        },
        # GROUP B: Visual Scam Communications
        {
            "id": "scam_acct_lock_01",
            "scenario": "account_suspension",
            "label": "scam",
            "group": "group_b_account_lock",
            "render_fn": render_modal_lockout,
            "title": "CRITICAL SECURITY WARNING",
            "body": [
                "YOUR BANK ACCOUNT HAS BEEN SUSPENDED!",
                "Unauthorized login detected from foreign IP.",
                "Verify identity within 30 minutes or funds",
                "will be permanently locked. bit.ly/unlock-hdfc",
            ],
            "notes": "Phishing modal popup on darkened overlay with urgency triangle.",
        },
        {
            "id": "scam_acct_lock_02",
            "scenario": "account_suspension",
            "label": "scam",
            "group": "group_b_account_lock",
            "render_fn": render_modal_lockout,
            "title": "SECURITY ALERT: LOCK ACTIVE",
            "body": [
                "Debit card access temporarily disabled.",
                "Suspicious UPI transactions observed.",
                "Restore credentials now: sbi-secure-portal.info",
            ],
            "notes": "Phishing modal lockout variant.",
        },
        {
            "id": "scam_lottery_01",
            "scenario": "fake_lottery",
            "label": "scam",
            "group": "group_b_lottery",
            "render_fn": render_lottery_coupon,
            "title": "CONGRATULATIONS LUCKY WINNER!",
            "body": [
                "Selected 1st prize winner in KBC Mega Draw!",
                "Winning Ticket No: KBC-992147",
                "Claim code: WIN-25L",
                "Visit www.kbc-reward-winner.top to claim.",
            ],
            "notes": "Gold lottery coupon voucher with prize seal.",
        },
        {
            "id": "scam_lottery_02",
            "scenario": "fake_lottery",
            "label": "scam",
            "group": "group_b_lottery",
            "render_fn": render_lottery_coupon,
            "title": "INTERNATIONAL LOTTERY PRIZE",
            "body": [
                "Your mobile number was awarded $50,000 USD.",
                "Pay mandatory customs fee Rs. 4,500 to release.",
                "WhatsApp Manager: +91 9876543210",
            ],
            "notes": "Lottery advance-fee voucher variant.",
        },
        {
            "id": "scam_kyc_01",
            "scenario": "kyc_renewal",
            "label": "scam",
            "group": "group_b_kyc",
            "render_fn": render_kyc_split_form,
            "title": "RBI MANDATORY KYC UPDATE NOTICE",
            "body": [
                "Dear customer, KYC validity has expired.",
                "SIM & UPI services will disconnect in 24 hours.",
                "Upload PAN and Aadhaar details below immediately.",
            ],
            "notes": "Phishing KYC split form with input boxes.",
        },
        {
            "id": "scam_kyc_02",
            "scenario": "kyc_renewal",
            "label": "scam",
            "group": "group_b_kyc",
            "render_fn": render_kyc_split_form,
            "title": "TELECOM OPERATOR KYC VERIFY",
            "body": [
                "Mobile connection scheduled for deactivation.",
                "Submit document details to prevent disconnection.",
                "Support line: support-desk-telecom.site",
            ],
            "notes": "Phishing KYC split form variant.",
        },
        {
            "id": "scam_qr_phish_01",
            "scenario": "qr_payment",
            "label": "scam",
            "group": "group_b_qr_phish",
            "render_fn": render_qr_phish_screen,
            "title": "TAX REFUND PENDING APPROVAL",
            "body": [
                "Approved Tax Refund: Rs. 14,280.00",
                "Scan QR code with UPI app to receive funds.",
                "Do NOT enter PIN when receiving.",
            ],
            "notes": "Large QR scam screen promising incoming refund.",
        },
        {
            "id": "scam_qr_phish_02",
            "scenario": "qr_payment",
            "label": "scam",
            "group": "group_b_qr_phish",
            "render_fn": render_qr_phish_screen,
            "title": "MARKETPLACE ESCROW RECEIPT",
            "body": [
                "Buyer payment of Rs. 8,500 ready for release.",
                "Scan QR code below in PhonePe to accept payment.",
                "Funds deposited directly into wallet.",
            ],
            "notes": "Marketplace QR refund scam layout.",
        },
        # GROUP C: Hard Negatives (Benign with scam-like features)
        {
            "id": "hard_neg_qr_01",
            "scenario": "qr_payment",
            "label": "non_scam",
            "group": "group_c_legit_qr",
            "render_fn": render_pos_receipt_qr,
            "title": "SmartBazaar Grocery Store POS-04",
            "body": [
                "Terminal: POS-04 | Cashier: Sunita R.",
                "Invoice #INV-2026-9812",
                "Items: 6 | Payment method: UPI Dynamic QR",
            ],
            "notes": "Legitimate retail POS receipt with payment QR.",
        },
        {
            "id": "hard_neg_qr_02",
            "scenario": "qr_payment",
            "label": "non_scam",
            "group": "group_c_legit_qr",
            "render_fn": render_pos_receipt_qr,
            "title": "Metro Transit Automated Fare Gate",
            "body": [
                "Bangalore Metro Rail Corporation Ltd.",
                "Single Journey Ticket: Majestic to Indiranagar",
                "Valid for: 120 minutes from issue.",
            ],
            "notes": "Legitimate transit gate receipt with ticket QR.",
        },
        {
            "id": "hard_neg_otp_01",
            "scenario": "otp_alert",
            "label": "non_scam",
            "group": "group_c_legit_otp",
            "render_fn": render_otp_keypad_dialog,
            "title": "ICICI Bank 3D Secure Verification",
            "body": [
                "Merchant: Amazon India | Amount: Rs. 2,499.00",
                "Card ending: **1104",
                "OTP sent to registered mobile ending 9821.",
            ],
            "notes": "Legitimate 3D secure OTP entry screen with boxes.",
        },
        {
            "id": "hard_neg_otp_02",
            "scenario": "otp_alert",
            "label": "non_scam",
            "group": "group_c_legit_otp",
            "render_fn": render_otp_keypad_dialog,
            "title": "ScamShield MFA Two-Factor Login",
            "body": [
                "Login for admin user: radika@scamshield.org",
                "Enter 6-digit code from authenticator app.",
                "Code refreshes in 30 seconds.",
            ],
            "notes": "Legitimate MFA OTP dialog screen.",
        },
        {
            "id": "hard_neg_alert_01",
            "scenario": "security_alert",
            "label": "non_scam",
            "group": "group_c_legit_urgent_alert",
            "render_fn": render_security_shield_alert,
            "title": "AXIS BANK FRAUD MONITORING",
            "body": [
                "ALERT: Unrecognized login attempt blocked.",
                "Source: IP 185.220.101.4 (Kyiv, Ukraine).",
                "No funds were debited from your account.",
                "If not you, freeze card inside mobile app.",
            ],
            "notes": "Legitimate bank fraud alert with security shield emblem.",
        },
        {
            "id": "hard_neg_alert_02",
            "scenario": "security_alert",
            "label": "non_scam",
            "group": "group_c_legit_urgent_alert",
            "render_fn": render_security_shield_alert,
            "title": "Google Account Security Warning",
            "body": [
                "Unrecognized Windows device sign-in detected.",
                "Location: Bengaluru, Karnataka, India.",
                "If this was you, ignore this message.",
                "If not you, review activity in Google Account.",
            ],
            "notes": "Legitimate security alert with dual action buttons.",
        },
        {
            "id": "hard_neg_card_01",
            "scenario": "card_payment",
            "label": "non_scam",
            "group": "group_c_legit_card_payment",
            "render_fn": render_credit_card_billing,
            "title": "SBI Card - Monthly Statement Due",
            "body": [
                "Card: SimplySAVE SBI Card (**6712)",
                "Total Amount Due: Rs. 6,840.50 | Due: 18 Sep 2026",
                "Pay securely via official SBI Card app.",
            ],
            "notes": "Legitimate credit card visual with chip and billing details.",
        },
        {
            "id": "hard_neg_card_02",
            "scenario": "card_payment",
            "label": "non_scam",
            "group": "group_c_legit_card_payment",
            "render_fn": render_credit_card_billing,
            "title": "HDFC Millennia Credit Card Bill",
            "body": [
                "Total Due: Rs. 4,320.00 | Min Due: Rs. 250.00",
                "Autopay scheduled for 22 Sep 2026.",
                "Manage card limits at netbanking.hdfcbank.com",
            ],
            "notes": "Credit card billing card variant.",
        },
        # PAIRED LAYOUT VARIANT: Same layout template, divergent text
        {
            "id": "paired_layout_scam",
            "scenario": "account_suspension",
            "label": "scam",
            "group": "group_paired_layout",
            "render_fn": render_standard_alert_card,
            "title": "SYSTEM ALERT: ACTION REQUIRED",
            "body": [
                "Your account access has been restricted.",
                "Verify identity immediately to avoid suspension.",
                "Failure to act will permanently deactivate account.",
                "Visit: secure-verify-portal.tk/auth",
            ],
            "paired_layout_id": "paired_layout_legit",
            "notes": "Paired layout: Scam text in standard red alert template.",
        },
        {
            "id": "paired_layout_legit",
            "scenario": "account_notice",
            "label": "non_scam",
            "group": "group_paired_layout",
            "render_fn": render_standard_alert_card,
            "title": "SYSTEM ALERT: ACTION REQUIRED",
            "body": [
                "Your annual privacy settings review is available.",
                "Please review preferred sharing options when free.",
                "No changes have been made to your current account.",
                "Settings can be accessed in your account dashboard.",
            ],
            "paired_layout_id": "paired_layout_scam",
            "notes": "Paired layout: Benign text in identical standard red alert template.",
        },
        # PAIRED TEXT VARIANT: Same scam text, divergent visual presentation
        {
            "id": "paired_text_styled",
            "scenario": "account_suspension",
            "label": "scam",
            "group": "group_paired_text",
            "render_fn": render_urgent_compromise_card,
            "title": "IMMEDIATE ACCOUNT LOCKOUT NOTICE",
            "body": [
                "Urgent: Your bank credentials have been compromised.",
                "Click below to restore access before 5:00 PM today.",
                "Failure will result in legal action and account closure.",
                "Verify at: hdfc-restore-kyc.net",
            ],
            "paired_text_id": "paired_text_plain",
            "notes": "Paired text: Scam text in styled red alert template.",
        },
        {
            "id": "paired_text_plain",
            "scenario": "account_suspension",
            "label": "scam",
            "group": "group_paired_text",
            "render_fn": render_plain_text_note,
            "title": "Notes App",
            "body": [
                "Urgent: Your bank credentials have been compromised.",
                "Click below to restore access before 5:00 PM today.",
                "Failure will result in legal action and account closure.",
                "Verify at: hdfc-restore-kyc.net",
            ],
            "paired_text_id": "paired_text_styled",
            "notes": "Paired text: Identical scam text in plain unstyled monochrome note.",
        },
    ]

    for spec in specs:
        img_id = spec["id"]
        img_filename = f"{img_id}.png"
        img_path = images_dir / img_filename

        render_fn = spec["render_fn"]
        if "chat_messages" in spec:
            render_fn(img_path, spec["title"], spec["chat_messages"])
            ground_truth = spec["title"] + "\n" + "\n".join(f"{s}: {m}" for s, m, _ in spec["chat_messages"])
        else:
            render_fn(img_path, spec["title"], spec["body"])
            ground_truth = spec["title"] + "\n" + "\n".join(spec["body"])

        img_hash = compute_image_sha256(img_path)
        p_hash = compute_dhash(img_path)

        record = VisualSampleRecord(
            image_id=img_id,
            image_path=str(img_path.relative_to(output_dir.parent.parent)),
            label=spec["label"],
            source_type="synthetic",
            scenario=spec["scenario"],
            pattern_group_id=spec["group"],
            paired_text_id=spec.get("paired_text_id"),
            paired_layout_id=spec.get("paired_layout_id"),
            ground_truth_text=ground_truth,
            visual_notes=spec.get("notes", ""),
            annotation_confidence=1.0,
            image_hash=img_hash,
            perceptual_hash=p_hash,
            split=None,
        )
        records.append(record)

    # Partition by pattern_group_id deterministically
    from .leakage import audit_visual_leakage, partition_by_group

    train_recs, val_recs, test_recs = partition_by_group(records)
    leakage_report = audit_visual_leakage(train_recs, val_recs, test_recs)

    manifest_path = meta_dir / "dataset_manifest.json"
    manifest_data = {
        "description": "ScamShield AI Phase 9B Controlled Visual Classification Dataset",
        "total_samples": len(records),
        "classes": {
            "scam": sum(1 for r in records if r.label == "scam"),
            "non_scam": sum(1 for r in records if r.label == "non_scam"),
        },
        "splits": {
            "train": len(train_recs),
            "val": len(val_recs),
            "test": len(test_recs),
        },
        "groups": sorted(list({r.pattern_group_id for r in records})),
        "leakage_audit": leakage_report.to_dict(),
        "records": [r.to_dict() for r in records],
    }

    manifest_path.write_text(json.dumps(manifest_data, indent=2), encoding="utf-8")
    (meta_dir / "leakage_report.json").write_text(
        json.dumps(leakage_report.to_dict(), indent=2), encoding="utf-8"
    )
    return records, manifest_path
