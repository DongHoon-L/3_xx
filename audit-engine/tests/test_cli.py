import base64
import json

import pytest

from audit_engine import AuditEvent, AuditRecorder
from audit_engine.chain import canonical_json
from audit_engine.cli import main

KEK_B64 = base64.b64encode(b"\x05" * 32).decode()


@pytest.fixture
def env(tmp_path, monkeypatch):
    values = {
        "AUDIT_PSEUDONYM_SECRET": "cli-test-secret-0123456789",
        "AUDIT_KEK_B64": KEK_B64,
        "AUDIT_CHAIN_PATH": str(tmp_path / "chain.jsonl"),
        "AUDIT_VAULT_PATH": str(tmp_path / "vault.json"),
    }
    for key, value in values.items():
        monkeypatch.setenv(key, value)
    return tmp_path


def event(record_id: str, timestamp: str = "2026-09-01T03:00:00Z", action: str = "agent_query") -> AuditEvent:
    return AuditEvent(timestamp, "alice", "analyst", "rag-users", action, "rag-agent/agent", record_id,
                      "127.0.0.1", "question text", "answered", {"tool": "rag_answer"})


def seed(env) -> AuditRecorder:
    recorder = AuditRecorder.from_env()
    recorder.record(event("req-1"), sensitive={"question": "내 이메일은 sample.user@example.com", "answer": "a"})
    recorder.record(event("req-old", timestamp="2020-01-01T00:00:00Z"), sensitive={"question": "old"})
    recorder.record(event("req-plain", action="auth_denied"))
    return recorder


def chain_actions(env) -> list[str]:
    lines = (env / "chain.jsonl").read_text(encoding="utf-8").splitlines()
    return [json.loads(line)["record"]["action"] for line in lines if line.strip()]


def test_verify_ok_and_after_tamper(env, capsys):
    seed(env)
    assert main(["verify"]) == 0
    assert json.loads(capsys.readouterr().out)["valid"] is True

    path = env / "chain.jsonl"
    rows = [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()]
    rows[0]["record"]["purpose"] = "tampered"
    path.write_text("".join(canonical_json(r) + "\n" for r in rows), encoding="utf-8")
    assert main(["verify"]) == 1
    out = json.loads(capsys.readouterr().out)
    assert out["valid"] is False and out["failed_seq"] == 1 and out["reason"] == "entry_hash_mismatch"


def test_report_json_and_exit_code(env, capsys):
    seed(env)
    out_file = env / "report.json"
    assert main(["report", "--out", str(out_file)]) == 0
    report = json.loads(out_file.read_text(encoding="utf-8"))
    assert report["entries"] == 3
    assert report["by_action"] == {"agent_query": 2, "auth_denied": 1}
    assert report["by_result"] == {"answered": 3}
    assert report["sealed_count"] == 2 and report["shredded_count"] == 0
    assert report["expired_count"] == 1 and report["expired_record_ids"] == ["req-old"]
    assert report["residual_plaintext_pii"] == 0
    assert report["verification"]["valid"] is True
    human = capsys.readouterr().out
    assert "entries: 3" in human and "chain: PASS" in human


def test_report_on_corrupt_chain_fails(env, capsys):
    seed(env)
    path = env / "chain.jsonl"
    path.write_text(path.read_text(encoding="utf-8") + "{broken\n", encoding="utf-8")
    assert main(["report"]) == 1
    assert "chain: FAIL" in capsys.readouterr().out


def test_unseal_then_shred_then_unseal_denied(env, capsys):
    seed(env)
    assert main(["unseal", "--record-id", "req-1", "--actor", "auditor"]) == 0
    assert json.loads(capsys.readouterr().out)["question"] == "내 이메일은 sample.user@example.com"

    assert main(["shred", "--record-id", "req-1", "--actor", "auditor"]) == 0
    assert json.loads(capsys.readouterr().out) == {"requested": ["req-1"], "shredded": ["req-1"]}

    assert main(["unseal", "--record-id", "req-1", "--actor", "auditor"]) == 1
    assert "denied" in capsys.readouterr().err

    assert chain_actions(env)[-3:] == ["audit_unseal", "audit_shred", "audit_unseal"]
    assert main(["verify"]) == 0


def test_shred_expired_only(env, capsys):
    recorder = seed(env)
    assert main(["shred", "--expired", "--actor", "auditor"]) == 0
    assert json.loads(capsys.readouterr().out) == {"requested": ["req-old"], "shredded": ["req-old"]}
    assert recorder.vault.has("req-1") and not recorder.vault.has("req-old")
    assert main(["shred", "--expired", "--actor", "auditor"]) == 1  # nothing left to shred


def test_shred_unknown_record_returns_1(env, capsys):
    seed(env)
    assert main(["shred", "--record-id", "nope", "--actor", "auditor"]) == 1


def test_shred_requires_actor(env):
    with pytest.raises(SystemExit) as exc:
        main(["shred", "--record-id", "req-1"])
    assert exc.value.code == 2


def test_keygen(capsys):
    assert main(["keygen"]) == 0
    key = capsys.readouterr().out.strip()
    assert len(base64.b64decode(key, validate=True)) == 32


def test_missing_secrets_fail_closed(env, monkeypatch, capsys):
    monkeypatch.delenv("AUDIT_KEK_B64")
    assert main(["shred", "--record-id", "x", "--actor", "a"]) == 1
    assert "AUDIT_KEK_B64" in capsys.readouterr().err


def test_shred_records_intent_before_destroying_keys(env, capsys):
    seed(env)
    vault = env / "vault.json"
    vault.unlink()
    vault.mkdir()  # every vault read/write now fails with AuditStorageError
    assert main(["shred", "--record-id", "req-1", "--actor", "auditor"]) == 1
    assert "error:" in capsys.readouterr().err
    assert chain_actions(env)[-1] == "audit_shred"  # intent was recorded even though the shred could not run


def test_report_unwritable_out_fails_cleanly(env, capsys):
    seed(env)
    assert main(["report", "--out", str(env)]) == 1  # a directory, not a file
    assert "error:" in capsys.readouterr().err
