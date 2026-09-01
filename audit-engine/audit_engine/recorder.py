"""AuditRecorder — the single add-on entry point: validate → pseudonymize → mask → seal → retention → append."""

from __future__ import annotations

import json
from typing import Any, Mapping

from .chain import ChainEntry, HashChain, canonical_json
from .config import AuditConfig
from .crypto import KeyVault, generate_key, seal, unseal
from .deidentification import pseudonymize_value
from .errors import AuditValidationError, SealIntegrityError
from .masking import mask_record
from .retention import RetentionPolicy
from .schema import AuditEvent

FREE_TEXT_FIELDS = ("purpose", "details")


def protect_record(event: AuditEvent, pseudonym_secret: bytes) -> dict:
    """Pseudonymize the actor and mask PII in free-text fields only.

    Identifiers, timestamps and controlled-vocabulary fields are left intact: masking them
    would let the card/RRN regexes corrupt UUID record_ids (breaking AAD/vault lookup) and hashes.
    """
    protected = event.to_dict()
    protected["actor"] = pseudonymize_value(event.actor, pseudonym_secret)
    for name in FREE_TEXT_FIELDS:
        protected[name], _findings = mask_record(protected[name])
    return protected


def residual_pii_count(record: dict) -> int:
    """How many PII patterns still match in a stored record's free-text fields (must be 0)."""
    return sum(len(mask_record(record.get(name, ""))[1]) for name in FREE_TEXT_FIELDS)


class AuditRecorder:
    """The add-on entry point: one recorder per service process, one service process per chain/vault.

    Run the service with a single writer (`uvicorn --workers 1`). The operator CLI may run while the
    service is up: chain and vault writes take a cross-process file lock and `HashChain.append`
    resyncs from the on-disk tail, so nothing is lost or forked — but the service pays an O(n)
    re-verify on its first append after a CLI write.

    `record()` blocks on fsync and rewrites the whole vault when `sensitive` is given; call it from a
    worker thread in async servers and translate `AuditError` into a fail-closed response.
    """

    def __init__(self, config: AuditConfig) -> None:
        self._config = config
        self._chain = HashChain.open(config.chain_path, config.hash_algorithm)
        self._vault = KeyVault(config.vault_path, config.kek)
        self._policy = RetentionPolicy(config.policy_path)

    @classmethod
    def from_env(cls, env: Mapping[str, str] | None = None) -> "AuditRecorder":
        return cls(AuditConfig.from_env(env))

    @property
    def config(self) -> AuditConfig:
        return self._config

    @property
    def chain(self) -> HashChain:
        return self._chain

    @property
    def vault(self) -> KeyVault:
        return self._vault

    @property
    def policy(self) -> RetentionPolicy:
        return self._policy

    def record(self, event: AuditEvent, sensitive: dict[str, Any] | None = None) -> ChainEntry:
        """Append one protected event. Raises AuditError subclasses; never swallows failures."""
        event.validate()
        protected = protect_record(event, self._config.pseudonym_secret)
        retention = self._policy.for_event(event)  # pure computation: keep chain.append the only step after put

        sealed = None
        if sensitive is not None:
            try:
                payload = canonical_json(sensitive).encode("utf-8")
            except (TypeError, ValueError) as exc:
                raise AuditValidationError("sensitive", "must be JSON-serializable") from exc
            dek = generate_key()
            sealed = seal(payload, dek, event.record_id.encode("utf-8"))
            self._vault.put(event.record_id, dek)  # rejects a duplicate record_id under the vault lock

        return self._chain.append(protected, sealed, retention)

    def unseal(self, entry: ChainEntry) -> dict:
        """Recover the sealed payload of an entry. Raises KeyNotFoundError if the key was shredded."""
        if entry.sealed is None:
            raise SealIntegrityError("entry has no sealed payload")
        record_id = str(entry.record["record_id"])
        dek = self._vault.get(record_id)
        return json.loads(unseal(entry.sealed, dek, record_id.encode("utf-8")).decode("utf-8"))
