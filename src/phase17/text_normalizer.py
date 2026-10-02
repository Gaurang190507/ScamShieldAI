"""Deterministic Obfuscation Normalizer for ScamShield AI Phase 17 (Fix #3).

Addresses character-spacing, punctuation-insertion, homoglyphs, and leetspeak
evasion techniques while strictly preserving:
- Original raw input text for evidence span grounding
- Legitimate multi-word sentences (e.g., 'hello world', 'a big dog')
- Legitimate phone numbers, dates, currency amounts, and URLs
- Multilingual scripts (Hindi Devanagari, Romanized Hinglish)
"""

import re
from typing import Dict, Tuple


# Common Cyrillic to Latin homoglyphs map
CYRILLIC_HOMOGLYPHS = {
    "\u0430": "a",  # Cyrillic small a
    "\u0435": "e",  # Cyrillic small e
    "\u043e": "o",  # Cyrillic small o
    "\u0440": "p",  # Cyrillic small er
    "\u0441": "c",  # Cyrillic small es
    "\u0443": "y",  # Cyrillic small u
    "\u0445": "x",  # Cyrillic small ha
    "\u0456": "i",  # Cyrillic small byelorussian-ukrainian i
    "\u0410": "A",  # Cyrillic capital A
    "\u0412": "B",  # Cyrillic capital Ve
    "\u0415": "E",  # Cyrillic capital E
    "\u041a": "K",  # Cyrillic capital Ka
    "\u041c": "M",  # Cyrillic capital Em
    "\u041d": "H",  # Cyrillic capital En
    "\u041e": "O",  # Cyrillic capital O
    "\u0420": "P",  # Cyrillic capital Er
    "\u0421": "C",  # Cyrillic capital Es
    "\u0422": "T",  # Cyrillic capital Te
    "\u0425": "X",  # Cyrillic capital Ha
}


class ObfuscationNormalizer:
    """Normalizes adversarial obfuscation for robust model inference."""

    @classmethod
    def normalize_homoglyphs(cls, text: str) -> Tuple[str, bool]:
        """Replaces deceptive Cyrillic homoglyphs with standard Latin equivalents."""
        changed = False
        chars = []
        for ch in text:
            if ch in CYRILLIC_HOMOGLYPHS:
                chars.append(CYRILLIC_HOMOGLYPHS[ch])
                changed = True
            else:
                chars.append(ch)
        return "".join(chars), changed

    @classmethod
    def defang_urls(cls, text: str) -> Tuple[str, bool]:
        """Restores defanged protocol and domain punctuation (e.g., hXXps:// or [.]) for analysis."""
        changed = False
        res = text

        # Defanged protocol
        new_res = re.sub(r"\bh[xX]{2}ps?://", lambda m: "https://" if "s" in m.group(0).lower() else "http://", res)
        if new_res != res:
            res = new_res
            changed = True

        # Defanged dots [.] or (dot)
        new_res = re.sub(r"\[\.\]", ".", res)
        if new_res != res:
            res = new_res
            changed = True

        new_res = re.sub(r"\(\.\)", ".", res)
        if new_res != res:
            res = new_res
            changed = True

        return res, changed

    @classmethod
    def collapse_spaced_characters(cls, text: str) -> Tuple[str, bool]:
        """Collapses artificially spaced single letters while preserving word boundaries.

        Example:
        'D e a r  c u s t o m e r' -> 'Dear customer'
        'hello world' -> 'hello world' (untouched)
        """
        changed = False

        def collapse_chunk(chunk: str) -> str:
            nonlocal changed
            raw = chunk.strip()
            if not raw:
                return chunk
            m = re.match(r"^(.*?)([\.,;!?:/]+)$", raw)
            trailing = ""
            core = raw
            if m:
                core, trailing = m.group(1), m.group(2)
            tokens = core.split()
            if len(tokens) >= 2 and all(len(t) == 1 for t in tokens):
                changed = True
                return "".join(tokens) + trailing
            return chunk

        # Split lines first
        lines = text.split("\n")
        new_lines = []

        for line in lines:
            # First handle comma-separated or multi-space separated single characters:
            # e.g., 'D e a r  c u s t o m e r, y o u r  b a n k'
            # Split by multi-space OR comma-space
            segments = re.split(r"(\s{2,}|\s*,\s*)", line)
            if len(segments) > 1:
                reconstructed = []
                for seg in segments:
                    if re.match(r"^\s+$", seg):
                        reconstructed.append(" ")
                    elif "," in seg:
                        reconstructed.append(", ")
                    else:
                        reconstructed.append(collapse_chunk(seg))
                line = "".join(reconstructed)
            else:
                line = collapse_chunk(line)

            # Handle period/dot/underscore/hyphen separated characters: e.g. Y.o.u.r or S-E-C-R-E-T or R_E_F_U_N_D
            def repl_punct(match):
                nonlocal changed
                seq = match.group(0)
                cleaned = re.sub(r"[\.\-_]", "", seq)
                if len(cleaned) >= 3:
                    changed = True
                    return cleaned
                return seq

            punct_pattern = r"\b[A-Za-z0-9](?:[\.\-_][A-Za-z0-9]){2,}\b"
            line = re.sub(punct_pattern, repl_punct, line)
            new_lines.append(line)

        return "\n".join(new_lines), changed

    @classmethod
    def normalize_leetspeak_in_context(cls, text: str) -> Tuple[str, bool]:
        """Normalizes targeted leetspeak substitutions within suspicious tokens."""
        changed = False

        # Common word-level leetspeak replacements
        leetspeak_tokens = {
            r"\bp@y\b": "pay",
            r"\bp@yp@l\b": "paypal",
            r"\burg3nt\b": "urgent",
            r"\bp3nding\b": "pending",
            r"\bb!ll\b": "bill",
            r"\bt0\b": "to",
            r"\bav0!d\b": "avoid",
            r"\bp0w3r\b": "power",
            r"\bc0nt@ct\b": "contact",
            r"\bd!sc0m\b": "discom",
            r"\b0ff!c3r\b": "officer",
        }

        res = text
        for pat, repl in leetspeak_tokens.items():
            new_res = re.sub(pat, repl, res, flags=re.IGNORECASE)
            if new_res != res:
                res = new_res
                changed = True

        return res, changed

    @classmethod
    def normalize_for_inference(cls, text: str) -> Tuple[str, Dict[str, bool]]:
        """Applies complete normalization pipeline returning clean text and audit flags."""
        if not text or not isinstance(text, str):
            return text, {"applied": False}

        orig = text
        audit: Dict[str, bool] = {
            "applied": False,
            "homoglyphs_replaced": False,
            "defanged_repaired": False,
            "spacing_collapsed": False,
            "leetspeak_normalized": False,
        }

        # 1. Homoglyphs
        t1, h_changed = cls.normalize_homoglyphs(orig)
        if h_changed:
            audit["homoglyphs_replaced"] = True

        # 2. Defanged URLs
        t2, d_changed = cls.defang_urls(t1)
        if d_changed:
            audit["defanged_repaired"] = True

        # 3. Collapse spaced characters and period/hyphen separations
        t3, s_changed = cls.collapse_spaced_characters(t2)
        if s_changed:
            audit["spacing_collapsed"] = True

        # 4. Leetspeak substitutions
        t4, l_changed = cls.normalize_leetspeak_in_context(t3)
        if l_changed:
            audit["leetspeak_normalized"] = True

        audit["applied"] = any([h_changed, d_changed, s_changed, l_changed])
        return t4, audit
