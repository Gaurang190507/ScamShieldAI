"""Conservative, deterministic text post-processing for OCR outputs in ScamShield AI.

OPERATIONAL PRINCIPLE:
- Traceability: OCR output must remain faithfully grounded in the visual source.
- Zero Semantic Rewriting: Never autocorrect suspicious or misspelled tokens (e.g., 'paypa1.com'
  must NOT be changed to 'paypal.com'; '0TP' must NOT be rewritten as 'OTP').
- Clean Structure: Normalizes extraneous whitespace and cross-platform line breaks while
  preserving exact casing, punctuation, URLs, phone numbers, and currency symbols.
"""

import re


def normalize_ocr_text(raw_text: str) -> str:
    """Normalizes raw OCR text deterministically without aggressive semantic correction.

    Performs:
    1. Line ending normalization (\\r\\n and \\r -> \\n).
    2. Horizontal whitespace collapse (multiple spaces/tabs -> single space).
    3. Multi-line whitespace cleanup (excessive blank lines collapsed to double newlines).
    4. Trimming accidental leading and trailing whitespace.

    Strictly preserves:
    - Verbatim characters, symbols, numbers, and casing.
    - URLs, email handles, phone numbers, currency symbols, and OTP tokens.

    Args:
        raw_text: String as directly returned by OCR engine.

    Returns:
        Cleaned, normalized string ready for downstream entity extraction and classification.
    """
    if not raw_text or not isinstance(raw_text, str):
        return ""

    # 1. Normalize line endings
    text = raw_text.replace("\r\n", "\n").replace("\r", "\n")

    # 2. Normalize horizontal spaces on each line
    lines = text.split("\n")
    cleaned_lines = []
    for line in lines:
        # Collapse multiple horizontal whitespace characters (spaces, tabs) into single space
        cleaned_line = re.sub(r"[ \t]+", " ", line).strip()
        cleaned_lines.append(cleaned_line)

    # 3. Collapse 3+ consecutive newlines into at most 2 newlines (preserving paragraph breaks)
    joined = "\n".join(cleaned_lines)
    collapsed = re.sub(r"\n{3,}", "\n\n", joined)

    # 4. Strip outer whitespace
    return collapsed.strip()
