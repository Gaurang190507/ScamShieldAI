"""Deterministic document chunker for ScamShield AI Phase 10 Knowledge Base.

Splits reference documents into coherent passages preserving full source provenance
and metadata attribution across every chunk.
"""

import re
from typing import List, Sequence

from .schemas import KnowledgeChunk, KnowledgeDocument


def chunk_document(
    doc: KnowledgeDocument,
    target_words_min: int = 80,
    target_words_max: int = 400,
) -> List[KnowledgeChunk]:
    """Splits a single KnowledgeDocument into semantic, bounded chunks.

    Splits primarily along section/paragraph breaks (double newlines or numbered items)
    while grouping small snippets to ensure coherent context.

    Args:
        doc: KnowledgeDocument instance to chunk.
        target_words_min: Minimum desired words per chunk before grouping.
        target_words_max: Maximum desired words per chunk before splitting.

    Returns:
        List of KnowledgeChunk instances.
    """
    raw_content = doc.content.strip()
    if not raw_content:
        return []

    # Split by section headers or double newlines
    # Matches patterns like "\n\n1. " or "\n\n"
    paragraphs = [p.strip() for p in re.split(r"\n\s*\n", raw_content) if p.strip()]

    chunks: List[KnowledgeChunk] = []
    current_text_blocks: List[str] = []
    current_words = 0

    def finalize_chunk(text_blocks: List[str], chunk_idx: int) -> KnowledgeChunk:
        joined_text = "\n\n".join(text_blocks).strip()
        words = len(joined_text.split())
        c_id = f"chunk_{chunk_idx:02d}"
        return KnowledgeChunk(
            chunk_id=c_id,
            document_id=doc.document_id,
            title=doc.title,
            source=doc.source,
            topic=doc.topic,
            text=joined_text,
            chunk_index=chunk_idx,
            word_count=words,
            metadata={
                "source_type": doc.source_type,
                "publication_date": doc.publication_date,
                "jurisdiction": doc.jurisdiction,
                "license_status": doc.license_status,
            },
        )

    for p in paragraphs:
        p_words = len(p.split())

        # If a single paragraph is larger than target_words_max, split it into sentences
        if p_words > target_words_max:
            # First flush any accumulated blocks
            if current_text_blocks:
                chunks.append(finalize_chunk(current_text_blocks, len(chunks) + 1))
                current_text_blocks = []
                current_words = 0

            # Split large paragraph by sentence
            sentences = [s.strip() for s in re.split(r"(?<=[.!?])\s+", p) if s.strip()]
            sub_blocks: List[str] = []
            sub_words = 0
            for s in sentences:
                s_len = len(s.split())
                if sub_words + s_len > target_words_max and sub_blocks:
                    chunks.append(finalize_chunk(sub_blocks, len(chunks) + 1))
                    sub_blocks = [s]
                    sub_words = s_len
                else:
                    sub_blocks.append(s)
                    sub_words += s_len
            if sub_blocks:
                chunks.append(finalize_chunk(sub_blocks, len(chunks) + 1))
            continue

        # Accumulate paragraph
        if current_words + p_words > target_words_max and current_text_blocks:
            chunks.append(finalize_chunk(current_text_blocks, len(chunks) + 1))
            current_text_blocks = [p]
            current_words = p_words
        else:
            current_text_blocks.append(p)
            current_words += p_words

    if current_text_blocks:
        chunks.append(finalize_chunk(current_text_blocks, len(chunks) + 1))

    return chunks


def chunk_all_documents(
    docs: Sequence[KnowledgeDocument],
    target_words_min: int = 80,
    target_words_max: int = 400,
) -> List[KnowledgeChunk]:
    """Chunks an entire collection of KnowledgeDocuments deterministically."""
    all_chunks: List[KnowledgeChunk] = []
    for doc in docs:
        all_chunks.extend(
            chunk_document(
                doc,
                target_words_min=target_words_min,
                target_words_max=target_words_max,
            )
        )
    return all_chunks
