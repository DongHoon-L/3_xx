"""Append-only JSONL hash chain. Each line is a self-describing entry linked by previous_hash."""

from __future__ import annotations

import hashlib
import json
import os
import threading
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterator

from .errors import AuditStorageError, ChainCorruptError

GENESIS_HASH = "GENESIS"
HASH_ALGORITHMS = ("sha256", "sha512", "sha3_256")
HASHED_FIELDS = ("seq", "record", "sealed", "retention", "previous_hash")


def canonical_json(obj: Any) -> str:
    return json.dumps(obj, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def compute_entry_hash(entry: dict, algorithm: str) -> str:
    payload = {name: entry[name] for name in HASHED_FIELDS}
    return hashlib.new(algorithm, canonical_json(payload).encode("utf-8")).hexdigest()


@dataclass(frozen=True)
class ChainEntry:
    seq: int
    record: dict
    sealed: dict | None
    retention: dict
    previous_hash: str
    entry_hash: str

    def to_dict(self) -> dict:
        return {
            "seq": self.seq,
            "record": self.record,
            "sealed": self.sealed,
            "retention": self.retention,
            "previous_hash": self.previous_hash,
            "entry_hash": self.entry_hash,
        }

    @classmethod
    def from_dict(cls, data: dict) -> "ChainEntry":
        seq = data["seq"]
        if not isinstance(seq, int) or isinstance(seq, bool):
            raise ValueError("seq must be an int")
        return cls(
            seq=seq,
            record=dict(data["record"]),
            sealed=None if data["sealed"] is None else dict(data["sealed"]),
            retention=dict(data["retention"]),
            previous_hash=str(data["previous_hash"]),
            entry_hash=str(data["entry_hash"]),
        )


@dataclass(frozen=True)
class ChainVerification:
    valid: bool
    entries_checked: int
    failed_seq: int | None = None
    reason: str | None = None


class HashChain:
    """Single-writer-process chain. Concurrency inside one process is serialized by a lock."""

    def __init__(self, path: str | os.PathLike[str], algorithm: str = "sha256") -> None:
        if algorithm not in HASH_ALGORITHMS:
            raise ValueError(f"unsupported hash algorithm {algorithm!r}; allowed: {HASH_ALGORITHMS}")
        self._path = Path(path)
        self._algorithm = algorithm
        self._lock = threading.Lock()
        self._last_seq = 0
        self._last_hash = GENESIS_HASH

    @property
    def path(self) -> Path:
        return self._path

    @classmethod
    def open(cls, path: str | os.PathLike[str], algorithm: str = "sha256") -> "HashChain":
        chain = cls(path, algorithm)
        verification, last_seq, last_hash = chain._walk()
        if not verification.valid:
            raise ChainCorruptError(
                f"chain {chain._path} failed verification at seq={verification.failed_seq}: {verification.reason}"
            )
        chain._last_seq, chain._last_hash = last_seq, last_hash
        return chain

    def verify(self) -> ChainVerification:
        return self._walk()[0]

    def _walk(self) -> tuple[ChainVerification, int, str]:
        expected_seq, expected_prev, checked = 1, GENESIS_HASH, 0
        if not self._path.exists():
            return ChainVerification(True, 0), 0, GENESIS_HASH
        try:
            with self._path.open("r", encoding="utf-8") as fh:
                for raw in fh:
                    line = raw.strip()
                    if not line:
                        continue
                    try:
                        entry = ChainEntry.from_dict(json.loads(line))
                    except (ValueError, KeyError, TypeError):
                        return ChainVerification(False, checked, expected_seq, "malformed_line"), 0, ""
                    if entry.seq != expected_seq:
                        return ChainVerification(False, checked, entry.seq, "seq_gap"), 0, ""
                    if entry.previous_hash != expected_prev:
                        return ChainVerification(False, checked, entry.seq, "previous_hash_mismatch"), 0, ""
                    if compute_entry_hash(entry.to_dict(), self._algorithm) != entry.entry_hash:
                        return ChainVerification(False, checked, entry.seq, "entry_hash_mismatch"), 0, ""
                    checked += 1
                    expected_seq += 1
                    expected_prev = entry.entry_hash
        except OSError as exc:
            raise AuditStorageError(f"cannot read chain {self._path}: {exc.__class__.__name__}") from exc
        return ChainVerification(True, checked), expected_seq - 1, expected_prev

    def append(self, record: dict, sealed: dict | None, retention: dict) -> ChainEntry:
        with self._lock:
            seq = self._last_seq + 1
            partial = {
                "seq": seq,
                "record": record,
                "sealed": sealed,
                "retention": retention,
                "previous_hash": self._last_hash,
            }
            entry = ChainEntry(**partial, entry_hash=compute_entry_hash(partial, self._algorithm))
            try:
                self._path.parent.mkdir(parents=True, exist_ok=True)
                with self._path.open("a", encoding="utf-8") as fh:
                    fh.write(canonical_json(entry.to_dict()) + "\n")
                    fh.flush()
                    os.fsync(fh.fileno())
            except OSError as exc:
                raise AuditStorageError(f"cannot append to chain {self._path}: {exc.__class__.__name__}") from exc
            self._last_seq, self._last_hash = seq, entry.entry_hash
            return entry

    def iter_entries(self) -> Iterator[ChainEntry]:
        if not self._path.exists():
            return
        try:
            with self._path.open("r", encoding="utf-8") as fh:
                for raw in fh:
                    line = raw.strip()
                    if line:
                        yield ChainEntry.from_dict(json.loads(line))
        except OSError as exc:
            raise AuditStorageError(f"cannot read chain {self._path}: {exc.__class__.__name__}") from exc
