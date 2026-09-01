"""Corpus loading. Documents are untrusted data — they are never executed, only retrieved and sanitized."""

from __future__ import annotations

import json
import os
from dataclasses import dataclass
from pathlib import Path

DEFAULT_DOCUMENTS_PATH = Path(__file__).parent / "data" / "documents.json"


@dataclass(frozen=True)
class Document:
    doc_id: str
    text: str


def load_documents(path: str | os.PathLike[str]) -> list[Document]:
    rows = json.loads(Path(path).read_text(encoding="utf-8"))
    if not isinstance(rows, list):
        raise ValueError("documents file must contain a JSON array")
    documents: list[Document] = []
    seen: set[str] = set()
    for index, row in enumerate(rows):
        if not isinstance(row, dict):
            raise ValueError(f"document #{index} must be an object")
        doc_id, text = row.get("doc_id"), row.get("text")
        if not isinstance(doc_id, str) or not doc_id.strip():
            raise ValueError(f"document #{index}: doc_id must be a non-empty string")
        if not isinstance(text, str) or not text.strip():
            raise ValueError(f"document {doc_id!r}: text must be a non-empty string")
        if doc_id in seen:
            raise ValueError(f"duplicate doc_id {doc_id!r}")
        seen.add(doc_id)
        documents.append(Document(doc_id=doc_id, text=text))
    return documents
