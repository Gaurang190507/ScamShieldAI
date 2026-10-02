"""Deterministic generator for Phase 9A local OCR test image fixtures.

Creates local, synthetic images using Pillow with zero network requests or downloads:
1. fixture_01_scam.png: Urgent account suspension message with link.
2. fixture_02_legitimate.png: Benign shipping notice.
3. fixture_03_payment.png: Lottery reward with payment demand in INR.
4. fixture_04_blank.png: Solid white image with zero text.
5. fixture_05_edge_case.png: Symbols (₹, @, :, /, ., OTP token, phone number).
"""

import json
from pathlib import Path
from typing import Dict, Any
from PIL import Image, ImageDraw, ImageFont


FIXTURE_DEFINITIONS: Dict[str, Dict[str, Any]] = {
    "fixture_01_scam.png": {
        "text": (
            "URGENT!\n"
            "Your bank account will be suspended today.\n"
            "Verify immediately:\n"
            "https://example.com/verify"
        ),
        "label": "scam",
        "description": "Scam-like screenshot with urgency and URL.",
        "width": 600,
        "height": 300,
    },
    "fixture_02_legitimate.png": {
        "text": (
            "Your order has been shipped.\n"
            "Expected delivery: tomorrow."
        ),
        "label": "non_scam",
        "description": "Legitimate shipping notification.",
        "width": 500,
        "height": 200,
    },
    "fixture_03_payment.png": {
        "text": (
            "Congratulations!\n"
            "You won ₹50,000.\n"
            "Pay ₹500 processing fee to claim your reward."
        ),
        "label": "scam",
        "description": "Advance fee payment request with currency.",
        "width": 600,
        "height": 250,
    },
    "fixture_04_blank.png": {
        "text": "",
        "label": "blank",
        "description": "Blank image containing zero text.",
        "width": 400,
        "height": 200,
    },
    "fixture_05_edge_case.png": {
        "text": (
            "Do not share your OTP 482910 with anyone.\n"
            "Support: help@bank-service.com\n"
            "Charges: ₹25.00\n"
            "Helpline: +91-9876543210\n"
            "Portal: https://secure.bank.com/auth"
        ),
        "label": "edge_case",
        "description": "Edge case containing symbols, OTP, email, URL, phone, and currency.",
        "width": 650,
        "height": 350,
    },
}


def generate_fixtures(output_dir: Path) -> Dict[str, Any]:
    """Generates synthetic image fixtures deterministically.

    Args:
        output_dir: Directory where image files and manifest are saved.

    Returns:
        Manifest dictionary mapping filenames to fixture metadata and ground-truth text.
    """
    output_dir.mkdir(parents=True, exist_ok=True)
    manifest: Dict[str, Any] = {}

    for filename, defn in FIXTURE_DEFINITIONS.items():
        img_path = output_dir / filename
        width = defn["width"]
        height = defn["height"]
        text = defn["text"]

        # Create plain clean background (white)
        img = Image.new("RGB", (width, height), color=(255, 255, 255))
        draw = ImageDraw.Draw(img)

        if text:
            # Draw text using default bitmap font
            # Position text with 20px margin
            draw.multiline_text(
                (25, 25),
                text,
                fill=(0, 0, 0),
                spacing=10,
            )

        # Save deterministically
        img.save(img_path, format="PNG")

        manifest[filename] = {
            "filename": filename,
            "filepath": str(img_path.resolve()),
            "ground_truth_text": text,
            "label": defn["label"],
            "description": defn["description"],
            "width": width,
            "height": height,
        }

    manifest_path = output_dir / "manifest.json"
    with open(manifest_path, "w", encoding="utf-8") as f:
        f.write(json.dumps(manifest, indent=2))

    return manifest


if __name__ == "__main__":
    out = Path(__file__).resolve().parent / "images"
    manifest = generate_fixtures(out)
    print(f"Generated {len(manifest)} image fixtures in: {out}")
