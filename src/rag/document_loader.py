"""Document loader for ScamShield AI Phase 10 Knowledge Base.

Loads and validates versioned reference documents from the local `data/knowledge_base/` directory.
Enforces zero external network calls and guarantees strict schema adherence.
"""

import json
from pathlib import Path
from typing import List, Optional, Union

from .schemas import KnowledgeDocument


REQUIRED_FIELDS = {
    "document_id",
    "title",
    "source",
    "source_type",
    "publication_date",
    "retrieval_date",
    "jurisdiction",
    "topic",
    "license_status",
    "content",
}


def load_knowledge_documents(
    kb_dir: Optional[Union[str, Path]] = None,
) -> List[KnowledgeDocument]:
    """Recursively scans and loads all knowledge base documents from disk.

    Args:
        kb_dir: Path to `data/knowledge_base/` directory. Defaults to standard repository path.

    Returns:
        List of validated KnowledgeDocument dataclass instances.
    """
    if kb_dir is None:
        kb_dir = Path(__file__).resolve().parents[2] / "data" / "knowledge_base"
    base_path = Path(kb_dir).resolve()

    if not base_path.is_dir():
        raise FileNotFoundError(f"Knowledge base directory not found at: {base_path}")

    documents: List[KnowledgeDocument] = []

    for file_path in sorted(base_path.glob("**/*.json")):
        # Skip manifests or non-document json files if any
        if file_path.name.startswith("manifest") or file_path.name.startswith("."):
            continue

        try:
            raw_text = file_path.read_text(encoding="utf-8")
            data = json.loads(raw_text)
        except Exception as e:
            raise ValueError(f"Failed to parse JSON in knowledge document '{file_path}': {e}") from e

        missing = REQUIRED_FIELDS - set(data.keys())
        if missing:
            raise ValueError(
                f"Knowledge document '{file_path}' is missing required fields: {sorted(list(missing))}"
            )

        doc = KnowledgeDocument(
            document_id=str(data["document_id"]).strip(),
            title=str(data["title"]).strip(),
            source=str(data["source"]).strip(),
            source_type=str(data["source_type"]).strip(),
            publication_date=str(data["publication_date"]).strip(),
            retrieval_date=str(data["retrieval_date"]).strip(),
            jurisdiction=str(data["jurisdiction"]).strip(),
            topic=str(data["topic"]).strip(),
            license_status=str(data["license_status"]).strip(),
            content=str(data["content"]).strip(),
            tags=list(data.get("tags", [])),
        )
        documents.append(doc)

    return documents
