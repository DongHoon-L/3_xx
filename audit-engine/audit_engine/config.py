"""Environment-driven configuration. Missing or weak secrets abort startup."""

from __future__ import annotations

import base64
import binascii
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Mapping

from .chain import HASH_ALGORITHMS
from .errors import AuditConfigError
from .retention import DEFAULT_POLICY_PATH

DEFAULT_CHAIN_PATH = "./audit-data/chain.jsonl"
DEFAULT_VAULT_PATH = "./audit-data/vault.json"
MIN_SECRET_CHARS = 16
KEK_BYTES = 32


@dataclass(frozen=True, repr=False)
class AuditConfig:
    pseudonym_secret: bytes
    kek: bytes
    chain_path: Path
    vault_path: Path
    policy_path: Path
    hash_algorithm: str

    def __repr__(self) -> str:  # never print secrets
        return (
            f"AuditConfig(chain_path={str(self.chain_path)!r}, vault_path={str(self.vault_path)!r}, "
            f"policy_path={str(self.policy_path)!r}, hash_algorithm={self.hash_algorithm!r}, secrets=<redacted>)"
        )

    @classmethod
    def from_env(cls, env: Mapping[str, str] | None = None) -> "AuditConfig":
        source = os.environ if env is None else env

        secret = source.get("AUDIT_PSEUDONYM_SECRET", "")
        if len(secret) < MIN_SECRET_CHARS:
            raise AuditConfigError(f"AUDIT_PSEUDONYM_SECRET must be set and at least {MIN_SECRET_CHARS} characters")

        try:
            kek = base64.b64decode(source.get("AUDIT_KEK_B64", ""), validate=True)
        except (ValueError, binascii.Error) as exc:
            raise AuditConfigError("AUDIT_KEK_B64 must be valid base64") from exc
        if len(kek) != KEK_BYTES:
            raise AuditConfigError(f"AUDIT_KEK_B64 must decode to exactly {KEK_BYTES} bytes")

        algorithm = source.get("AUDIT_HASH_ALGORITHM", "sha256")
        if algorithm not in HASH_ALGORITHMS:
            raise AuditConfigError(f"AUDIT_HASH_ALGORITHM must be one of {HASH_ALGORITHMS}")

        policy_path = Path(source.get("AUDIT_RETENTION_POLICY", str(DEFAULT_POLICY_PATH)))
        if not policy_path.is_file():
            raise AuditConfigError(f"AUDIT_RETENTION_POLICY file not found: {policy_path}")

        return cls(
            pseudonym_secret=secret.encode("utf-8"),
            kek=kek,
            chain_path=Path(source.get("AUDIT_CHAIN_PATH", DEFAULT_CHAIN_PATH)),
            vault_path=Path(source.get("AUDIT_VAULT_PATH", DEFAULT_VAULT_PATH)),
            policy_path=policy_path,
            hash_algorithm=algorithm,
        )
