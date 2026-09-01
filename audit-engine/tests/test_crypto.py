import json

import pytest

from audit_engine.crypto import KEY_BYTES, KeyVault, generate_key, seal, unseal, vault_record_ids
from audit_engine.errors import AuditStorageError, KeyNotFoundError, SealIntegrityError

KEK = b"\x01" * 32
OTHER_KEK = b"\x02" * 32


def test_generate_key_length_and_randomness():
    a, b = generate_key(), generate_key()
    assert len(a) == KEY_BYTES == 32 and a != b


def test_seal_unseal_round_trip():
    dek = generate_key()
    sealed = seal("비밀 질문 sk-abc".encode("utf-8"), dek, b"req-1")
    assert sealed["alg"] == "AES-256-GCM"
    assert set(sealed) == {"alg", "nonce_b64", "ciphertext_b64"}
    assert unseal(sealed, dek, b"req-1") == "비밀 질문 sk-abc".encode("utf-8")


def test_unseal_with_wrong_aad_fails():
    dek = generate_key()
    sealed = seal(b"payload", dek, b"req-1")
    with pytest.raises(SealIntegrityError):
        unseal(sealed, dek, b"req-2")


def test_unseal_with_wrong_key_or_tampered_ciphertext_fails():
    dek = generate_key()
    sealed = seal(b"payload", dek, b"req-1")
    with pytest.raises(SealIntegrityError):
        unseal(sealed, generate_key(), b"req-1")
    tampered = dict(sealed, ciphertext_b64="AAAA" + sealed["ciphertext_b64"][4:])
    with pytest.raises(SealIntegrityError):
        unseal(tampered, dek, b"req-1")


def test_unseal_rejects_unknown_alg():
    with pytest.raises(SealIntegrityError):
        unseal({"alg": "XOR", "nonce_b64": "AA==", "ciphertext_b64": "AA=="}, generate_key(), b"x")


def test_vault_put_get_has_shred(tmp_path):
    vault = KeyVault(tmp_path / "vault.json", KEK)
    dek = generate_key()
    assert not vault.has("req-1")
    vault.put("req-1", dek)
    assert vault.has("req-1") and vault.get("req-1") == dek
    assert vault.shred("req-1") is True
    assert vault.shred("req-1") is False
    with pytest.raises(KeyNotFoundError):
        vault.get("req-1")


def test_vault_file_never_contains_raw_dek(tmp_path):
    path = tmp_path / "vault.json"
    dek = generate_key()
    KeyVault(path, KEK).put("req-1", dek)
    raw = path.read_bytes()
    assert dek not in raw
    stored = json.loads(raw)["req-1"]
    assert set(stored) == {"nonce_b64", "wrapped_b64"}


def test_vault_get_with_wrong_kek_fails(tmp_path):
    path = tmp_path / "vault.json"
    KeyVault(path, KEK).put("req-1", generate_key())
    with pytest.raises(SealIntegrityError):
        KeyVault(path, OTHER_KEK).get("req-1")


def test_vault_requires_32_byte_kek(tmp_path):
    with pytest.raises(ValueError):
        KeyVault(tmp_path / "v.json", b"short")


def test_vault_record_ids_without_kek(tmp_path):
    path = tmp_path / "vault.json"
    assert vault_record_ids(path) == set()
    vault = KeyVault(path, KEK)
    vault.put("a", generate_key())
    vault.put("b", generate_key())
    vault.shred("a")
    assert vault_record_ids(path) == {"b"}


def test_vault_unwritable_raises_storage_error(tmp_path):
    blocked = tmp_path / "vault.json"
    blocked.mkdir()
    with pytest.raises(AuditStorageError):
        KeyVault(blocked, KEK).put("req-1", generate_key())


def test_failed_save_leaves_no_temp_file(tmp_path):
    blocked = tmp_path / "vault.json"
    blocked.mkdir()
    with pytest.raises(AuditStorageError):
        KeyVault(blocked, KEK).put("req-1", generate_key())
    assert list(tmp_path.glob(".vault-*.tmp")) == []
