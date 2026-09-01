import base64
from pathlib import Path

import pytest

from audit_engine.config import DEFAULT_CHAIN_PATH, DEFAULT_VAULT_PATH, AuditConfig
from audit_engine.errors import AuditConfigError
from audit_engine.retention import DEFAULT_POLICY_PATH

GOOD_KEK = base64.b64encode(b"\x07" * 32).decode()


def good_env(**overrides) -> dict:
    env = {"AUDIT_PSEUDONYM_SECRET": "test-pseudonym-secret-0123", "AUDIT_KEK_B64": GOOD_KEK}
    env.update(overrides)
    return env


def test_defaults():
    cfg = AuditConfig.from_env(good_env())
    assert cfg.pseudonym_secret == b"test-pseudonym-secret-0123"
    assert cfg.kek == b"\x07" * 32
    assert cfg.chain_path == Path(DEFAULT_CHAIN_PATH) == Path("./audit-data/chain.jsonl")
    assert cfg.vault_path == Path(DEFAULT_VAULT_PATH) == Path("./audit-data/vault.json")
    assert cfg.policy_path == DEFAULT_POLICY_PATH
    assert cfg.hash_algorithm == "sha256"


def test_overrides(tmp_path):
    policy = tmp_path / "p.json"
    policy.write_text('{"default_policy": {"retention_days": 1}}', encoding="utf-8")
    cfg = AuditConfig.from_env(good_env(
        AUDIT_CHAIN_PATH=str(tmp_path / "c.jsonl"),
        AUDIT_VAULT_PATH=str(tmp_path / "v.json"),
        AUDIT_RETENTION_POLICY=str(policy),
        AUDIT_HASH_ALGORITHM="sha512",
    ))
    assert cfg.chain_path == tmp_path / "c.jsonl" and cfg.vault_path == tmp_path / "v.json"
    assert cfg.policy_path == policy and cfg.hash_algorithm == "sha512"


@pytest.mark.parametrize("missing", ["AUDIT_PSEUDONYM_SECRET", "AUDIT_KEK_B64"])
def test_missing_required_env_fails_closed(missing):
    env = good_env()
    del env[missing]
    with pytest.raises(AuditConfigError):
        AuditConfig.from_env(env)


def test_short_pseudonym_secret_rejected():
    with pytest.raises(AuditConfigError):
        AuditConfig.from_env(good_env(AUDIT_PSEUDONYM_SECRET="short"))


@pytest.mark.parametrize("bad", ["not-base64!!", base64.b64encode(b"\x01" * 16).decode()])
def test_bad_kek_rejected(bad):
    with pytest.raises(AuditConfigError):
        AuditConfig.from_env(good_env(AUDIT_KEK_B64=bad))


def test_hash_algorithm_allowlist():
    with pytest.raises(AuditConfigError):
        AuditConfig.from_env(good_env(AUDIT_HASH_ALGORITHM="md5"))


def test_missing_policy_file_rejected(tmp_path):
    with pytest.raises(AuditConfigError):
        AuditConfig.from_env(good_env(AUDIT_RETENTION_POLICY=str(tmp_path / "nope.json")))


def test_repr_hides_secrets():
    text = repr(AuditConfig.from_env(good_env()))
    assert "test-pseudonym-secret" not in text and GOOD_KEK not in text and "\\x07" not in text
