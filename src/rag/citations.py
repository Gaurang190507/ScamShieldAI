"""Internal citation formatting and validation utilities for ScamShield AI Phase 10.

Manages citation identifiers:
- Case Evidence: `[CASE:<evidence_id>]` (e.g., `[CASE:E1]`, `[CASE:ev_urgency_01]`)
- Knowledge Base: `[KB:<document_id>:<chunk_id>]` (e.g., `[KB:doc_i4c_citizen_guidelines:chunk_01]`)

Enforces strict provenance validation to prevent hallucinated citations.
"""

import re
from typing import Dict, List, Optional, Sequence, Set, Tuple

from src.aggregation.schemas import EvidenceItem
from .schemas import RetrievedChunk

# Regex patterns for detecting citation tags
CASE_CITATION_REGEX = re.compile(r"\[CASE:([a-zA-Z0-9_\-]+)\]")
KB_CITATION_REGEX = re.compile(r"\[KB:([a-zA-Z0-9_\-]+):([a-zA-Z0-9_\-]+)\]")


def format_case_citation(evidence_id: str) -> str:
    """Formats standard case evidence citation string."""
    clean_id = evidence_id.strip()
    return f"[CASE:{clean_id}]"


def format_kb_citation(document_id: str, chunk_id: str) -> str:
    """Formats standard knowledge base citation string."""
    return f"[KB:{document_id.strip()}:{chunk_id.strip()}]"


def extract_citations(text: str) -> Dict[str, List[str]]:
    """Extracts all CASE and KB citation tags found in a text string.

    Returns:
        Dictionary with keys "case_citations" and "kb_citations".
    """
    if not isinstance(text, str):
        return {"case_citations": [], "kb_citations": []}

    case_matches = [f"[CASE:{m}]" for m in CASE_CITATION_REGEX.findall(text)]
    kb_raw = KB_CITATION_REGEX.findall(text)
    kb_matches = [f"[KB:{doc}:{chk}]" for doc, chk in kb_raw]

    return {
        "case_citations": sorted(list(set(case_matches))),
        "kb_citations": sorted(list(set(kb_matches))),
    }


def validate_citations(
    text: str,
    valid_evidence_items: Sequence[EvidenceItem],
    retrieved_chunks: Sequence[RetrievedChunk],
) -> Tuple[bool, List[str]]:
    """Validates that all citation tags in the text refer to authentic, supplied sources.

    Args:
        text: Generated explanation text.
        valid_evidence_items: Upstream deterministic evidence items provided in context.
        retrieved_chunks: Upstream knowledge chunks supplied in context.

    Returns:
        Tuple of (is_valid: bool, errors: List[str]).
    """
    errors: List[str] = []

    # Valid sets
    valid_case_ids: Set[str] = {e.evidence_id.lower() for e in valid_evidence_items}
    # Also allow standard numeric aliases like E1, E2 if evidence_id was indexed
    for idx, e in enumerate(valid_evidence_items, start=1):
        valid_case_ids.add(f"e{idx}")
        valid_case_ids.add(f"ev{idx}")

    valid_kb_pairs: Set[Tuple[str, str]] = {
        (c.document_id.lower(), c.chunk_id.lower()) for c in retrieved_chunks
    }

    # Extract tags
    case_refs = CASE_CITATION_REGEX.findall(text)
    for ref in case_refs:
        if ref.lower() not in valid_case_ids:
            errors.append(
                f"Invalid case evidence citation '[CASE:{ref}]': Not present in supplied case evidence."
            )

    kb_refs = KB_CITATION_REGEX.findall(text)
    for doc_id, chunk_id in kb_refs:
        pair = (doc_id.lower(), chunk_id.lower())
        if pair not in valid_kb_pairs:
            errors.append(
                f"Invalid knowledge citation '[KB:{doc_id}:{chunk_id}]': Chunk was not retrieved for this case."
            )

    return (len(errors) == 0, errors)
