"""AES-256-GCM sealing of sensitive payloads and a KEK-wrapped data-key vault (crypto-shredding)."""

from __future__ import annotations

import base64
import json
import os
import secrets
import tempfile
import threading
from pathlib import Path

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from .errors import AuditStorageError, AuditValidationError, KeyNotFoundError, SealIntegrityError
from .filelock import exclusive_lock, lock_path_for

SEAL_ALGORITHM = "AES-256-GCM"
KEY_BYTES = 32
NONCE_BYTES = 12


def _b64e(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def _b64d(text: str) -> bytes:
    return base64.b64decode(text, validate=True)


def generate_key() -> bytes:
    return secrets.token_bytes(KEY_BYTES)


def seal(plaintext: bytes, dek: bytes, aad: bytes) -> dict:
    nonce = secrets.token_bytes(NONCE_BYTES)
    ciphertext = AESGCM(dek).encrypt(nonce, plaintext, aad)
    return {"alg": SEAL_ALGORITHM, "nonce_b64": _b64e(nonce), "ciphertext_b64": _b64e(ciphertext)}


def unseal(sealed: dict, dek: bytes, aad: bytes) -> bytes:
    if not isinstance(sealed, dict) or sealed.get("alg") != SEAL_ALGORITHM:
        raise SealIntegrityError("unsupported or missing seal algorithm")
    try:
        return AESGCM(dek).decrypt(_b64d(sealed["nonce_b64"]), _b64d(sealed["ciphertext_b64"]), aad)
    except (InvalidTag, KeyError, ValueError, TypeError) as exc:
        raise SealIntegrityError("sealed payload failed authentication") from exc


def _read_vault(file: Path) -> dict:
    """Parse the vault JSON. A file that exists but is not a JSON object is a storage error, not {}."""
    if not file.exists():
        return {}
    try:
        data = json.loads(file.read_text(encoding="utf-8"))
    except OSError as exc:
        raise AuditStorageError(f"cannot read vault {file}: {exc.__class__.__name__}") from exc
    except ValueError as exc:  # JSONDecodeError, UnicodeDecodeError
        raise AuditStorageError(f"vault {file} is corrupt: not valid JSON") from exc
    if not isinstance(data, dict):
        raise AuditStorageError(f"vault {file} is corrupt: expected a JSON object")
    return data


def vault_record_ids(path: str | os.PathLike[str]) -> set[str]:
    return set(_read_vault(Path(path)))


class KeyVault:
    """JSON file {record_id: {nonce_b64, wrapped_b64}}; DEKs are wrapped with the KEK (AES-GCM, aad=record_id).

    Every load→mutate→save sequence runs under both a thread lock and a cross-process file lock, so a
    concurrent operator CLI cannot drop a freshly stored key by writing back a stale copy of the file.
    """

    def __init__(self, path: str | os.PathLike[str], kek: bytes) -> None:
        if len(kek) != KEY_BYTES:
            raise ValueError("KEK must be exactly 32 bytes")
        self._path = Path(path)
        self._kek = AESGCM(kek)
        self._lock = threading.Lock()
        self._lock_path = lock_path_for(self._path)

    def _load(self) -> dict:
        return _read_vault(self._path)

    def _save(self, vault: dict) -> None:
        tmp_name: str | None = None
        try:
            self._path.parent.mkdir(parents=True, exist_ok=True)
            fd, tmp_name = tempfile.mkstemp(dir=self._path.parent, prefix=".vault-", suffix=".tmp")
            with os.fdopen(fd, "w", encoding="utf-8") as fh:
                json.dump(vault, fh, indent=2, sort_keys=True)
                fh.flush()
                os.fsync(fh.fileno())
            os.replace(tmp_name, self._path)
            tmp_name = None  # replaced successfully; nothing to clean up
        except OSError as exc:
            raise AuditStorageError(f"cannot write vault {self._path}: {exc.__class__.__name__}") from exc
        finally:
            if tmp_name is not None and os.path.exists(tmp_name):
                os.unlink(tmp_name)

    def put(self, record_id: str, dek: bytes) -> None:
        nonce = secrets.token_bytes(NONCE_BYTES)
        wrapped = self._kek.encrypt(nonce, dek, record_id.encode("utf-8"))
        with self._lock, exclusive_lock(self._lock_path):
            vault = self._load()
            if record_id in vault:  # the vault is authoritative: never overwrite a live data key
                raise AuditValidationError("record_id", "a data key already exists for this record_id")
            vault[record_id] = {"nonce_b64": _b64e(nonce), "wrapped_b64": _b64e(wrapped)}
            self._save(vault)

    def has(self, record_id: str) -> bool:
        with self._lock, exclusive_lock(self._lock_path):
            return record_id in self._load()

    def get(self, record_id: str) -> bytes:
        with self._lock, exclusive_lock(self._lock_path):
            entry = self._load().get(record_id)
        if entry is None:
            raise KeyNotFoundError(f"no data key for record {record_id!r} (never stored or shredded)")
        try:
            return self._kek.decrypt(_b64d(entry["nonce_b64"]), _b64d(entry["wrapped_b64"]), record_id.encode("utf-8"))
        except (InvalidTag, KeyError, ValueError, TypeError) as exc:
            raise SealIntegrityError(f"wrapped key for record {record_id!r} failed authentication") from exc

    def shred(self, record_id: str) -> bool:
        with self._lock, exclusive_lock(self._lock_path):
            vault = self._load()
            if record_id not in vault:
                return False
            del vault[record_id]
            self._save(vault)
            return True
