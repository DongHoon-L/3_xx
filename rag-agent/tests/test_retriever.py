from rag_agent.documents import DEFAULT_DOCUMENTS_PATH, Document, load_documents
from rag_agent.retriever import Retriever, tokenize

DOCS = load_documents(DEFAULT_DOCUMENTS_PATH)


def test_tokenize_lowercases_and_adds_hangul_bigrams():
    assert tokenize("Hello WORLD 123") == ["hello", "world", "123"]
    assert tokenize("날씨는") == ["날씨는", "날씨", "씨는"]
    assert tokenize("비") == ["비"]


def test_korean_weather_query_hits_weather_first():
    hits = Retriever(DOCS).search("서울 여름 날씨 어때?", top_k=2)
    assert hits and hits[0].document.doc_id == "weather"
    assert all(h.score > 0 for h in hits)
    assert [h.score for h in hits] == sorted((h.score for h in hits), reverse=True)


def test_support_hours_query_hits_policy():
    hits = Retriever(DOCS).search("주말에 고객 지원 받을 수 있어?", top_k=1)
    assert [h.document.doc_id for h in hits] == ["policy"]


def test_unrelated_query_returns_empty():
    assert Retriever(DOCS).search("quantum entanglement", top_k=3) == []


def test_top_k_and_determinism():
    retriever = Retriever(DOCS)
    first = retriever.search("API 키 연동 가이드", top_k=1)
    assert len(first) == 1 and first[0].document.doc_id == "api_guide"
    assert retriever.search("API 키 연동 가이드", top_k=1) == first


def test_ties_keep_document_order():
    docs = [Document("a", "alpha beta"), Document("b", "alpha beta")]
    hits = Retriever(docs).search("alpha", top_k=2)
    assert [h.document.doc_id for h in hits] == ["a", "b"]
