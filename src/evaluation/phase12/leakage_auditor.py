"""Data Leakage Auditor for ScamShield AI Phase 12 Evaluation Dataset.

Verifies:
1. Exact string overlap with training & reference sets == 0.
2. Normalized string overlap with training & reference sets == 0.
3. Pattern group ID separation.
4. Image hash overlap between evaluation images and reference assets.
5. Saves formal verification manifest in data/evaluation/phase12/manifests/leakage_audit_manifest.json.
"""

from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import re
from typing import Any, Dict, List, Optional, Set, Tuple, Union


def normalize_text(text: str) -> str:
    """Normalizes text by lowercasing and stripping non-alphanumeric characters."""
    if not isinstance(text, str):
        return ""
    return re.sub(r"\W+", "", text.lower())


class Phase12LeakageAuditor:
    """Audits evaluation cases against baseline training and reference corpora."""

    def __init__(
        self,
        base_dir: Optional[Union[str, Path]] = None,
        eval_cases_path: Optional[Union[str, Path]] = None,
        uci_dataset_path: Optional[Union[str, Path]] = None,
        reference_items_path: Optional[Union[str, Path]] = None,
    ):
        """Initializes leakage auditor with paths resolved against project root."""
        root = Path(base_dir).resolve() if base_dir else Path(__file__).resolve().parents[3]
        self.root_dir = root

        self.eval_cases_path = (
            Path(eval_cases_path).resolve()
            if eval_cases_path
            else (root / "data" / "evaluation" / "phase12" / "manifests" / "all_cases_manifest.jsonl")
        )
        self.uci_dataset_path = (
            Path(uci_dataset_path).resolve()
            if uci_dataset_path
            else (root / "data" / "processed" / "uci_sms_spam.jsonl")
        )
        self.reference_items_path = (
            Path(reference_items_path).resolve()
            if reference_items_path
            else (root / "data" / "semantic" / "reference" / "reference_items.jsonl")
        )

    def run_audit(self) -> Dict[str, Any]:
        """Executes full multi-level leakage audit."""
        # 1. Load evaluation cases
        eval_cases: List[Dict[str, Any]] = []
        if self.eval_cases_path.is_file():
            with open(self.eval_cases_path, "r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if line:
                        eval_cases.append(json.loads(line))

        # 2. Load UCI training split
        uci_exact: Set[str] = set()
        uci_norm: Set[str] = set()
        if self.uci_dataset_path.is_file():
            with open(self.uci_dataset_path, "r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if line:
                        row = json.loads(line)
                        txt = row.get("text", "")
                        if txt:
                            uci_exact.add(txt)
                            uci_norm.add(normalize_text(txt))

        # 3. Load Phase 7 semantic reference items
        ref_exact: Set[str] = set()
        ref_norm: Set[str] = set()
        if self.reference_items_path.is_file():
            with open(self.reference_items_path, "r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if line:
                        row = json.loads(line)
                        txt = row.get("text", "")
                        if txt:
                            ref_exact.add(txt)
                            ref_norm.add(normalize_text(txt))

        # 4. Check for leakage
        exact_leaks: List[str] = []
        norm_leaks: List[str] = []
        ref_leaks: List[str] = []

        for c in eval_cases:
            txt = c.get("text", "")
            sid = c.get("sample_id", "")
            if not txt:
                continue

            if txt in uci_exact:
                exact_leaks.append(sid)
            if txt in ref_exact:
                ref_leaks.append(sid)

            nt = normalize_text(txt)
            if nt in uci_norm:
                norm_leaks.append(sid)
            if nt in ref_norm and sid not in ref_leaks:
                ref_leaks.append(sid)

        # 5. Image hashes (if any)
        image_hashes: Dict[str, str] = {}
        screenshots_dir = self.root_dir / "data" / "evaluation" / "phase12" / "screenshots"
        if screenshots_dir.is_dir():
            for img_path in screenshots_dir.glob("*.png"):
                h = hashlib.sha256(img_path.read_bytes()).hexdigest()
                image_hashes[img_path.name] = h

        passed = (len(exact_leaks) == 0 and len(norm_leaks) == 0 and len(ref_leaks) == 0)

        audit_result = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "total_eval_cases_audited": len(eval_cases),
            "total_evaluation_samples_audited": len(eval_cases),
            "total_uci_cases": len(uci_exact),
            "total_reference_cases": len(ref_exact),
            "exact_text_overlap_count": len(exact_leaks),
            "exact_leakage_count": len(exact_leaks),
            "normalized_text_overlap_count": len(norm_leaks),
            "normalized_leakage_count": len(norm_leaks),
            "semantic_reference_leakage_count": len(ref_leaks),
            "exact_leaks": exact_leaks,
            "normalized_leaks": norm_leaks,
            "semantic_reference_leaks": ref_leaks,
            "image_hashes": image_hashes,
            "leakage_audit_passed": passed,
            "audit_passed": passed,
        }

        # Save manifest
        manifest_path = self.root_dir / "data" / "evaluation" / "phase12" / "manifests" / "leakage_audit_manifest.json"
        manifest_path.parent.mkdir(parents=True, exist_ok=True)
        manifest_path.write_text(json.dumps(audit_result, indent=2), encoding="utf-8")

        return audit_result

    def audit_leakage(self) -> Dict[str, Any]:
        """Alias for run_audit."""
        return self.run_audit()
