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
from .filelock import exclusive_lock, lock_path_for

GENESIS_HASH = "GENESIS"
HASH_ALGORITHMS = ("sha256", "sha512", "sha3_256")
HASHED_FIELDS = ("seq", "record", "sealed", "retention", "previous_hash")
TAIL_CHUNK_BYTES = 4096


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
    """Append-only chain, serialized by a thread lock inside the process and a file lock across processes.

    `open()` is the preferred constructor: it verifies the whole file up front and refuses a corrupt
    chain. A plain `HashChain(path)` starts with an empty in-memory tail; `append()` compares its
    cached `(seq, entry_hash)` with the last line on disk and, whenever they differ (another process
    appended, or the file was rewritten), re-walks the chain and resyncs — or raises `ChainCorruptError`
    if that walk fails. The chain is therefore never forked, at the cost of an O(n) re-verify on the
    first append after a foreign write.
    """

    def __init__(self, path: str | os.PathLike[str], algorithm: str = "sha256") -> None:
        if algorithm not in HASH_ALGORITHMS:
            raise ValueError(f"unsupported hash algorithm {algorithm!r}; allowed: {HASH_ALGORITHMS}")
        self._path = Path(path)
        self._algorithm = algorithm
        self._lock = threading.Lock()
        self._lock_path = lock_path_for(self._path)
        self._last_seq = 0
        self._last_hash = GENESIS_HASH

    @property
    def path(self) -> Path:
        return self._path

    @classmethod
    def open(cls, path: str | os.PathLike[str], algorithm: str = "sha256") -> "HashChain":
        chain = cls(path, algorithm)
        chain._resync()
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

    def _last_line(self) -> str | None:
        """The last non-empty line of the chain file, read from the end (None if absent or empty)."""
        if not self._path.exists():
            return None
        try:
            with self._path.open("rb") as fh:
                fh.seek(0, os.SEEK_END)
                position, tail = fh.tell(), b""
                while position > 0:
                    step = min(TAIL_CHUNK_BYTES, position)
                    position -= step
                    fh.seek(position)
                    tail = fh.read(step) + tail
                    trimmed = tail.rstrip()
                    if b"\n" in trimmed:
                        return trimmed[trimmed.rindex(b"\n") + 1:].decode("utf-8", "replace")
        except OSError as exc:
            raise AuditStorageError(f"cannot read chain {self._path}: {exc.__class__.__name__}") from exc
        trimmed = tail.strip()
        return trimmed.decode("utf-8", "replace") if trimmed else None

    def _tail_is_current(self) -> bool:
        """True when the on-disk tail is intact and is exactly the entry this instance last wrote."""
        line = self._last_line()
        if line is None:
            return self._last_seq == 0 and self._last_hash == GENESIS_HASH
        try:
            entry = ChainEntry.from_dict(json.loads(line))
        except (ValueError, KeyError, TypeError):
            return False
        if (entry.seq, entry.entry_hash) != (self._last_seq, self._last_hash):
            return False
        # The link matches, but the tail entry itself may have been edited without touching its
        # entry_hash; recomputing it costs one hash and stops us extending a tampered tail.
        return compute_entry_hash(entry.to_dict(), self._algorithm) == entry.entry_hash

    def _resync(self) -> None:
        """Re-verify the whole file and adopt its tail. Fail closed rather than fork the chain."""
        verification, last_seq, last_hash = self._walk()
        if not verification.valid:
            raise ChainCorruptError(
                f"chain {self._path} failed verification at seq={verification.failed_seq}: {verification.reason}"
            )
        self._last_seq, self._last_hash = last_seq, last_hash

    def append(self, record: dict, sealed: dict | None, retention: dict) -> ChainEntry:
        with self._lock, exclusive_lock(self._lock_path):
            if not self._tail_is_current():
                self._resync()
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
