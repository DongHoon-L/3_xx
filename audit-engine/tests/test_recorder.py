import base64
import json

import pytest

from audit_engine import AuditEvent, AuditRecorder
from audit_engine.config import AuditConfig
from audit_engine.crypto import KeyVault
from audit_engine.errors import (
    AuditConfigError,
    AuditError,
    AuditStorageError,
    AuditValidationError,
    KeyNotFoundError,
    SealIntegrityError,
)
from audit_engine.recorder import residual_pii_count

KEK = b"\x09" * 32
SECRET = "recorder-test-secret-000"
PII_QUESTION = "내 이메일 sample.user@example.com 으로 답장 줘"


def env_for(tmp_path, **overrides) -> dict:
    env = {
        "AUDIT_PSEUDONYM_SECRET": SECRET,
        "AUDIT_KEK_B64": base64.b64encode(KEK).decode(),
        "AUDIT_CHAIN_PATH": str(tmp_path / "chain.jsonl"),
        "AUDIT_VAULT_PATH": str(tmp_path / "vault.json"),
    }
    env.update(overrides)
    return env


def make_event(record_id="req-1", actor="alice", purpose=PII_QUESTION, **overrides) -> AuditEvent:
    base = dict(
        timestamp="2026-09-01T03:00:00Z", actor=actor, role="analyst", department="rag-users",
        action="agent_query", asset="rag-agent/agent", record_id=record_id, source_ip="127.0.0.1",
        purpose=purpose, result="answered", details={"tool": "rag_answer"},
    )
    base.update(overrides)
    return AuditEvent(**base)


@pytest.fixture
def recorder(tmp_path) -> AuditRecorder:
    return AuditRecorder.from_env(env_for(tmp_path))


def test_record_protects_actor_and_pii_in_chain(recorder, tmp_path):
    entry = recorder.record(make_event(), sensitive={"question": PII_QUESTION, "answer": "ok", "contexts": []})
    assert entry.seq == 1
    assert entry.record["actor"].startswith("P-") and entry.record["actor"] != "alice"
    assert "example.com" not in entry.record["purpose"]
    assert entry.record["details"] == {"tool": "rag_answer"}
    raw = (tmp_path / "chain.jsonl").read_text(encoding="utf-8")
    assert "alice" not in raw and "example.com" not in raw
    assert residual_pii_count(entry.record) == 0
    assert entry.record["record_id"] == "req-1" and entry.record["timestamp"] == "2026-09-01T03:00:00Z"
    assert entry.retention["retention_days"] == 365 and entry.retention["retention_until"] == "2027-09-01"


def test_identifiers_are_never_masked(recorder):
    # A UUID-shaped record_id contains digit groups that the card regex would otherwise eat.
    uuid_like = "11111111-2222-3333-4444-555555555555"
    entry = recorder.record(make_event(record_id=uuid_like, purpose="card 4111-1111-1111-1111"), sensitive={"q": "x"})
    assert entry.record["record_id"] == uuid_like
    assert entry.record["purpose"] == "card [CARD_MASKED]"
    assert recorder.unseal(entry) == {"q": "x"}


def test_sensitive_payload_is_sealed_and_recoverable(recorder):
    entry = recorder.record(make_event(), sensitive={"question": PII_QUESTION, "answer": "ok", "contexts": ["c1"]})
    assert entry.sealed is not None and entry.sealed["alg"] == "AES-256-GCM"
    assert recorder.unseal(entry) == {"question": PII_QUESTION, "answer": "ok", "contexts": ["c1"]}
    assert recorder.vault.has("req-1")


def test_record_without_sensitive_has_no_seal_and_no_key(recorder):
    entry = recorder.record(make_event(action="auth_denied", actor="anonymous", purpose="-"))
    assert entry.sealed is None and not recorder.vault.has("req-1")
    with pytest.raises(SealIntegrityError):
        recorder.unseal(entry)


def test_shred_makes_payload_unrecoverable_but_chain_valid(recorder):
    entry = recorder.record(make_event(), sensitive={"question": "q"})
    assert recorder.vault.shred("req-1") is True
    with pytest.raises(KeyNotFoundError):
        recorder.unseal(entry)
    assert recorder.chain.verify().valid


def test_invalid_event_is_rejected_before_writing(recorder, tmp_path):
    with pytest.raises(AuditValidationError):
        recorder.record(make_event(actor="   "))
    assert not (tmp_path / "chain.jsonl").exists()


def test_duplicate_record_id_with_sensitive_rejected(recorder):
    recorder.record(make_event(), sensitive={"q": 1})
    with pytest.raises(AuditValidationError) as exc:
        recorder.record(make_event(), sensitive={"q": 2})
    assert exc.value.field == "record_id"


def test_non_serializable_sensitive_is_a_validation_error(recorder, tmp_path):
    with pytest.raises(AuditValidationError) as exc:
        recorder.record(make_event(), sensitive={"question": object()})
    assert exc.value.field == "sensitive"
    assert not (tmp_path / "chain.jsonl").exists() and not recorder.vault.has("req-1")


def test_corrupt_vault_propagates_as_storage_error(tmp_path):
    recorder = AuditRecorder.from_env(env_for(tmp_path))
    (tmp_path / "vault.json").write_text("{not json", encoding="utf-8")
    with pytest.raises(AuditStorageError):
        recorder.record(make_event(), sensitive={"q": "x"})


def test_retention_failure_leaves_no_orphan_key(recorder, monkeypatch):
    """Retention is computed before the DEK is stored, so a policy failure cannot orphan a key."""
    def boom(event):
        raise AuditValidationError("timestamp", "boom")

    monkeypatch.setattr(recorder.policy, "for_event", boom)
    with pytest.raises(AuditValidationError):
        recorder.record(make_event(), sensitive={"q": "x"})
    assert not recorder.vault.has("req-1")


def test_storage_failure_propagates_as_audit_error(tmp_path):
    recorder = AuditRecorder.from_env(env_for(tmp_path))
    (tmp_path / "chain.jsonl").mkdir()  # make the chain path unwritable
    with pytest.raises(AuditStorageError) as exc:
        recorder.record(make_event())
    assert isinstance(exc.value, AuditError)


def test_reopen_continues_chain(tmp_path):
    env = env_for(tmp_path)
    AuditRecorder.from_env(env).record(make_event(record_id="a"))
    second = AuditRecorder.from_env(env).record(make_event(record_id="b"))
    assert second.seq == 2


def test_malformed_policy_file_fails_startup(tmp_path):
    policy = tmp_path / "policy.json"
    policy.write_text('{"default_policy": {"legal_basis": "no days"}}', encoding="utf-8")
    with pytest.raises(AuditConfigError):
        AuditRecorder.from_env(env_for(tmp_path, AUDIT_RETENTION_POLICY=str(policy)))


def test_from_env_reads_process_environment(tmp_path, monkeypatch):
    for key, value in env_for(tmp_path).items():
        monkeypatch.setenv(key, value)
    assert isinstance(AuditRecorder.from_env().config, AuditConfig)


def test_vault_type(recorder):
    assert isinstance(recorder.vault, KeyVault)
