import json

import pytest

from rag_agent.documents import DEFAULT_DOCUMENTS_PATH, Document, load_documents


def test_default_corpus_loads_four_synthetic_documents():
    docs = load_documents(DEFAULT_DOCUMENTS_PATH)
    assert [d.doc_id for d in docs] == ["weather", "policy", "api_guide", "poisoned"]
    assert all(isinstance(d, Document) and d.text for d in docs)
    assert "sk-proj-DEMO1234567890" in docs[2].text
    assert "SYSTEM OVERRIDE" in docs[3].text


def test_duplicate_doc_id_rejected(tmp_path):
    path = tmp_path / "docs.json"
    path.write_text(json.dumps([{"doc_id": "a", "text": "x"}, {"doc_id": "a", "text": "y"}]), encoding="utf-8")
    with pytest.raises(ValueError):
        load_documents(path)


@pytest.mark.parametrize("payload", ['{"doc_id": "a"}', '[{"doc_id": "a"}]', '[{"doc_id": 1, "text": "x"}]', '[{"doc_id": "a", "text": ""}]'])
def test_malformed_corpus_rejected(tmp_path, payload):
    path = tmp_path / "docs.json"
    path.write_text(payload, encoding="utf-8")
    with pytest.raises(ValueError):
        load_documents(path)
