import base64
import hashlib

import pytest

from audit_engine import AuditRecorder, AuditStorageError
from audit_engine.recorder import residual_pii_count
from rag_agent.agent import AgentTrace
from rag_agent.audit_hook import AuditHook
from rag_agent.auth import Principal

ALICE = Principal("alice", "analyst")


def audit_env(tmp_path) -> dict:
    return {
        "AUDIT_PSEUDONYM_SECRET": "hook-test-secret-0123456789",
        "AUDIT_KEK_B64": base64.b64encode(b"\x03" * 32).decode(),
        "AUDIT_CHAIN_PATH": str(tmp_path / "chain.jsonl"),
        "AUDIT_VAULT_PATH": str(tmp_path / "vault.json"),
    }


def make_trace(**overrides) -> AgentTrace:
    base = dict(
        request_id="11111111-2222-3333-4444-555555555555", question="내 메일 sample.user@example.com 로 날씨 알려줘",
        status="answered", tool="rag_answer", reason="코퍼스 관련도 0.42", guard_findings=(), context_findings=("SR-03:doc-urgency",),
        doc_ids=("weather", "policy"), contexts_sanitized=("[doc:weather]\n...",), answer="서울은 덥다", llm_model="qwen",
        latency_ms=37, output_masked=False, error=None,
    )
    base.update(overrides)
    return AgentTrace(**base)


@pytest.fixture
def recorder(tmp_path):
    return AuditRecorder.from_env(audit_env(tmp_path))


def test_answered_query_event(recorder, tmp_path):
    entry = AuditHook(recorder).record_query(make_trace(), ALICE, "10.0.0.7")
    record = entry.record
    assert record["action"] == "agent_query" and record["result"] == "answered"
    assert record["actor"].startswith("P-") and record["role"] == "analyst" and record["department"] == "rag-users"
    assert record["asset"] == "rag-agent/agent" and record["source_ip"] == "10.0.0.7"
    assert record["record_id"] == "11111111-2222-3333-4444-555555555555"
    assert "example.com" not in record["purpose"] and "[EMAIL_MASKED]" in record["purpose"]
    # base64url, not hex: a hex digest can contain a 16-digit run that mask_record rewrites as a card number
    expected_digest = base64.urlsafe_b64encode(hashlib.sha256("서울은 덥다".encode("utf-8")).digest()).decode().rstrip("=")
    assert record["details"] == {
        "tool": "rag_answer", "reason": "코퍼스 관련도 0.42", "doc_ids": "weather,policy", "guard_findings": "",
        "context_findings": "SR-03:doc-urgency", "llm_model": "qwen", "latency_ms": "37",
        "answer_digest_b64url": expected_digest, "output_masked": "false",
    }
    assert recorder.unseal(entry) == {"question": "내 메일 sample.user@example.com 로 날씨 알려줘", "answer": "서울은 덥다", "contexts": ["[doc:weather]\n..."]}
    assert residual_pii_count(entry.record) == 0
    assert "alice" not in (tmp_path / "chain.jsonl").read_text(encoding="utf-8")


def test_blocked_query_event(recorder):
    trace = make_trace(status="blocked", tool="none", reason="guard", guard_findings=("SR-01:system-override", "SR-02:ask-api-key"),
                       doc_ids=(), contexts_sanitized=(), answer=None, llm_model="", context_findings=())
    record = AuditHook(recorder).record_query(trace, ALICE, "10.0.0.7").record
    assert record["action"] == "agent_query_blocked"
    assert record["result"] == "blocked:SR-01:system-override,SR-02:ask-api-key"
    assert record["details"]["answer_digest_b64url"] == "" and record["details"]["guard_findings"] == "SR-01:system-override,SR-02:ask-api-key"


def test_error_query_event(recorder):
    trace = make_trace(status="error", error="unavailable", answer=None, llm_model="", doc_ids=(), contexts_sanitized=(), context_findings=())
    record = AuditHook(recorder).record_query(trace, ALICE, "10.0.0.7").record
    assert record["action"] == "agent_query" and record["result"] == "error:unavailable"


def test_auth_denied_event(recorder):
    entry = AuditHook(recorder).record_auth_denied("10.0.0.9", "invalid_token")
    record = entry.record
    assert record["action"] == "auth_denied" and record["result"] == "denied:invalid_token"
    assert record["role"] == "unauthenticated" and record["department"] == "-" and record["purpose"] == "-"
    assert record["details"] == {"reason": "invalid_token"} and entry.sealed is None
    assert len(record["record_id"]) == 36


def test_long_question_is_truncated_in_purpose_but_sealed_fully(recorder):
    long_question = "가" * 500
    entry = AuditHook(recorder).record_query(make_trace(question=long_question), ALICE, "1.1.1.1")
    assert len(entry.record["purpose"]) == 200
    assert recorder.unseal(entry)["question"] == long_question


def test_audit_failure_propagates(tmp_path):
    recorder = AuditRecorder.from_env(audit_env(tmp_path))
    (tmp_path / "chain.jsonl").mkdir()
    with pytest.raises(AuditStorageError):
        AuditHook(recorder).record_auth_denied("1.1.1.1", "missing_token")
