# Audit Engine (audit-engine/) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** `3_5`의 감사 엔진을 독립 패키지 `audit_engine`으로 이식·개선한다 — 증분 JSONL 해시체인, AES-256-GCM 봉인 + KEK 래핑 볼트(crypto-shredding), env 주입 가명화, fail-closed 검증, `verify/report/shred/unseal/keygen` CLI.

**Architecture:** 순수 파이썬 패키지. `AuditRecorder.record(event, sensitive)`가 단일 진입점으로 validate → 가명화 → 마스킹 → 봉인 → 보존 계산 → 체인 append를 수행하고 모든 실패를 `AuditError` 하위 예외로 전파한다. 체인은 append-only JSONL, 원문은 엔트리 안에 암호문으로 봉인되며 DEK는 KEK로 래핑되어 별도 볼트 JSON에 저장된다.

**Tech Stack:** Python 3.14 (venv `../../prism`), `cryptography>=42` (AESGCM), stdlib (`hashlib`, `hmac`, `json`, `threading`, `argparse`), `pytest>=8`.

**Spec:** `docs/superpowers/specs/2026-09-01-rag-audit-addon-design.md` §4, §7, §8

## Global Constraints

- 인터프리터: 항상 `../../prism/Scripts/python.exe` (3_xx 기준). 아래 모든 명령은 저장소 루트 `3_xx/`에서 실행한다. 표기 `PY` = `../../prism/Scripts/python.exe`.
- 브랜치: `feat/rag-audit-addon` (이미 생성됨). `main` 직접 커밋 금지.
- `ch3/3_5`, `ch1/*` 원본은 읽기만 한다. 절대 수정하지 않는다.
- 새 런타임 의존성은 `cryptography`뿐. dev 의존성은 `pytest`뿐. 그 외 패키지 추가 금지.
- 비밀값(`AUDIT_PSEUDONYM_SECRET`, `AUDIT_KEK_B64`)은 절대 로그·`repr`·예외 메시지에 넣지 않는다. 테스트는 명백히 가짜인 값만 사용한다.
- 모든 실패는 fail-closed: 예외를 삼키고 기본값으로 넘어가는 코드는 쓰지 않는다.
- 타임스탬프 형식은 정확히 `%Y-%m-%dT%H:%M:%SZ` (UTC).
- 정규 JSON은 정확히 `json.dumps(obj, ensure_ascii=False, sort_keys=True, separators=(",", ":"))` → UTF-8.
- 해시 알고리즘 허용목록: `sha256`(기본), `sha512`, `sha3_256`. 제네시스 previous_hash: `"GENESIS"`.
- **매 태스크의 커밋에는 `PROCESS.md` 갱신을 포함한다** (섹션 `### [P1-TN] <태스크명>`: 한 일 / 테스트 결과 / 특이사항).
- 커밋은 **사용자 단독 저자**로 남긴다: `Co-Authored-By` 트레일러를 절대 넣지 않는다 (사용자 요청). 커밋 메시지 끝에는 다음 한 줄만 붙인다:
  ```
  Claude-Session: https://claude.ai/code/session_01Uk8js6oJDEnhN2SJkDjzau
  ```
- 스펙 대비 의도된 차이(구현 편의): 예외 클래스는 `audit_engine/errors.py` 한 파일에 모은다(순환 import 방지). 파일 I/O 실패를 감싸는 `AuditStorageError`를 추가한다(rag-agent가 503으로 매핑할 수 있도록 `OSError`를 `AuditError`로 변환).

## File Structure

| 파일 | 책임 |
|---|---|
| `pytest.ini` (저장소 루트) | 두 패키지 테스트를 한 번에 돌리기 위한 `--import-mode=importlib`, `testpaths` |
| `.gitignore` | `.env`, `audit-data/`, 캐시류 |
| `audit-engine/pyproject.toml` | 패키지 메타데이터, 의존성, package-data(policies) |
| `audit-engine/audit_engine/__init__.py` | 공개 API re-export |
| `audit-engine/audit_engine/errors.py` | 예외 계층 |
| `audit-engine/audit_engine/schema.py` | `AuditEvent`, `validate`, `utc_now`, `parse_timestamp` |
| `audit-engine/audit_engine/chain.py` | `canonical_json`, `ChainEntry`, `ChainVerification`, `HashChain` |
| `audit-engine/audit_engine/crypto.py` | `seal`/`unseal`, `generate_key`, `KeyVault`, `vault_record_ids` |
| `audit-engine/audit_engine/masking.py` | 3_5 이식 (변경 없음) |
| `audit-engine/audit_engine/deidentification.py` | 3_5 이식 (secret 필수) |
| `audit-engine/audit_engine/retention.py` | `RetentionPolicy` |
| `audit-engine/audit_engine/policies/retention_policy.json` | 보존 정책 |
| `audit-engine/audit_engine/config.py` | `AuditConfig.from_env` |
| `audit-engine/audit_engine/recorder.py` | `AuditRecorder` |
| `audit-engine/audit_engine/cli.py`, `__main__.py` | CLI |
| `audit-engine/tests/test_*.py` | 모듈별 테스트 |

---

### Task 1: 스캐폴딩 — 패키지, 예외, pytest 설정, 설치

**Files:**
- Create: `pytest.ini`, `.gitignore`
- Create: `audit-engine/pyproject.toml`
- Create: `audit-engine/audit_engine/__init__.py`, `audit-engine/audit_engine/errors.py`
- Test: `audit-engine/tests/test_errors.py`

**Interfaces:**
- Produces: `audit_engine.errors.{AuditError, AuditValidationError(field, reason), AuditConfigError, ChainCorruptError, AuditStorageError, KeyNotFoundError, SealIntegrityError}`; `audit_engine.__version__ == "0.1.0"`

- [ ] **Step 1: 루트 설정 파일 작성**

`pytest.ini`:
```ini
[pytest]
addopts = --import-mode=importlib -q
testpaths = audit-engine/tests rag-agent/tests
```

`.gitignore`:
```gitignore
.env
audit-data/
__pycache__/
*.pyc
.pytest_cache/
*.egg-info/
build/
dist/
```

- [ ] **Step 2: pyproject 작성**

`audit-engine/pyproject.toml`:
```toml
[build-system]
requires = ["setuptools>=68"]
build-backend = "setuptools.build_meta"

[project]
name = "audit-engine"
version = "0.1.0"
description = "Tamper-evident 5W1H audit engine: JSONL hash chain, AES-GCM sealing, crypto-shredding, PII masking"
requires-python = ">=3.11"
dependencies = ["cryptography>=42"]

[project.optional-dependencies]
dev = ["pytest>=8"]

[tool.setuptools.packages.find]
include = ["audit_engine*"]

[tool.setuptools.package-data]
audit_engine = ["policies/*.json"]
```

- [ ] **Step 3: 실패하는 테스트 작성**

`audit-engine/tests/test_errors.py`:
```python
import audit_engine
from audit_engine.errors import (
    AuditConfigError,
    AuditError,
    AuditStorageError,
    AuditValidationError,
    ChainCorruptError,
    KeyNotFoundError,
    SealIntegrityError,
)


def test_version():
    assert audit_engine.__version__ == "0.1.0"


def test_all_errors_derive_from_audit_error():
    for cls in (AuditConfigError, AuditStorageError, ChainCorruptError, KeyNotFoundError, SealIntegrityError):
        assert issubclass(cls, AuditError)


def test_validation_error_carries_field_and_reason():
    err = AuditValidationError("actor", "must be non-empty")
    assert isinstance(err, AuditError)
    assert err.field == "actor"
    assert err.reason == "must be non-empty"
    assert str(err) == "actor: must be non-empty"
```

- [ ] **Step 4: 테스트 실패 확인**

Run: `PY -m pytest audit-engine/tests/test_errors.py`
Expected: FAIL — `ModuleNotFoundError: No module named 'audit_engine'`

- [ ] **Step 5: 패키지 파일 작성**

`audit-engine/audit_engine/errors.py`:
```python
"""Exception hierarchy for audit-engine. Callers catch AuditError to fail closed."""


class AuditError(Exception):
    """Base class for every audit-engine failure."""


class AuditValidationError(AuditError):
    """An AuditEvent (or a value derived from one) failed validation."""

    def __init__(self, field: str, reason: str) -> None:
        super().__init__(f"{field}: {reason}")
        self.field = field
        self.reason = reason


class AuditConfigError(AuditError):
    """Required configuration is missing or invalid."""


class ChainCorruptError(AuditError):
    """The on-disk hash chain failed verification; appending is refused."""


class AuditStorageError(AuditError):
    """A chain or vault file could not be read or written."""


class KeyNotFoundError(AuditError):
    """The data key for a record is absent from the vault (never stored or shredded)."""


class SealIntegrityError(AuditError):
    """AES-GCM authentication failed or the sealed payload is malformed."""
```

`audit-engine/audit_engine/__init__.py`:
```python
"""audit_engine — tamper-evident 5W1H audit engine (public API is filled in by later tasks)."""

__version__ = "0.1.0"
```

- [ ] **Step 6: editable 설치 (+pytest)**

Run: `PY -m pip install -e audit-engine pytest`
Expected: `Successfully installed audit-engine-0.1.0 ...` (cryptography는 이미 설치됨)

- [ ] **Step 7: 테스트 통과 확인**

Run: `PY -m pytest audit-engine/tests/test_errors.py`
Expected: `3 passed`

- [ ] **Step 8: PROCESS.md 기록 + 커밋**

`PROCESS.md` 끝에 추가:
```markdown

### [P1-T1] audit-engine 스캐폴딩
- `pytest.ini`(importlib 모드), `.gitignore`, `audit-engine/pyproject.toml`, `errors.py`(예외 7종), `__init__.py` 작성. venv에 editable 설치 + pytest 설치.
- 테스트: `test_errors.py` 3 passed.
```

```bash
git add pytest.ini .gitignore audit-engine PROCESS.md
git commit -m "feat(audit-engine): scaffold package with error hierarchy and pytest config"
```
(커밋 메시지 끝에 Global Constraints의 트레일러 두 줄 포함 — 이하 모든 커밋 동일)

---

### Task 2: `schema.py` — AuditEvent + fail-closed validate

**Files:**
- Create: `audit-engine/audit_engine/schema.py`
- Test: `audit-engine/tests/test_schema.py`

**Interfaces:**
- Consumes: `errors.AuditValidationError`
- Produces:
  - `TIMESTAMP_FORMAT = "%Y-%m-%dT%H:%M:%SZ"`
  - `utc_now() -> str`
  - `parse_timestamp(value: str) -> datetime` (tz=UTC; 실패 시 `AuditValidationError("timestamp", ...)`)
  - `AuditEvent(timestamp, actor, role, department, action, asset, record_id, source_ip, purpose, result, details={})` frozen dataclass, `.validate() -> None`, `.to_dict() -> dict`, `AuditEvent.from_dict(d)`

- [ ] **Step 1: 실패하는 테스트 작성**

`audit-engine/tests/test_schema.py`:
```python
import pytest

from audit_engine.errors import AuditValidationError
from audit_engine.schema import TIMESTAMP_FORMAT, AuditEvent, parse_timestamp, utc_now


def make_event(**overrides) -> AuditEvent:
    base = dict(
        timestamp="2026-09-01T03:00:00Z",
        actor="alice",
        role="analyst",
        department="rag-users",
        action="agent_query",
        asset="rag-agent/agent",
        record_id="req-001",
        source_ip="127.0.0.1",
        purpose="what is the weather",
        result="answered",
        details={"tool": "rag_answer"},
    )
    base.update(overrides)
    return AuditEvent(**base)


def test_valid_event_passes():
    make_event().validate()


@pytest.mark.parametrize("field", ["actor", "action", "asset", "record_id", "timestamp"])
def test_required_fields_reject_blank(field):
    with pytest.raises(AuditValidationError) as exc:
        make_event(**{field: "   "}).validate()
    assert exc.value.field == field


@pytest.mark.parametrize("bad", ["2026-09-01 03:00:00", "2026-09-01T03:00:00+09:00", "not-a-date", "2026-09-01T03:00:00"])
def test_timestamp_must_be_utc_z_format(bad):
    with pytest.raises(AuditValidationError) as exc:
        make_event(timestamp=bad).validate()
    assert exc.value.field == "timestamp"


def test_details_must_be_flat_string_map():
    with pytest.raises(AuditValidationError) as exc:
        make_event(details={"latency_ms": 12}).validate()
    assert exc.value.field == "details"


def test_utc_now_matches_format():
    parse_timestamp(utc_now())
    assert utc_now().endswith("Z")
    assert TIMESTAMP_FORMAT == "%Y-%m-%dT%H:%M:%SZ"


def test_round_trip_dict():
    event = make_event()
    assert AuditEvent.from_dict(event.to_dict()) == event
    assert event.to_dict()["details"] == {"tool": "rag_answer"}
```

- [ ] **Step 2: 테스트 실패 확인**

Run: `PY -m pytest audit-engine/tests/test_schema.py`
Expected: FAIL — `ModuleNotFoundError: No module named 'audit_engine.schema'`

- [ ] **Step 3: 구현**

`audit-engine/audit_engine/schema.py`:
```python
"""5W1H audit event schema with fail-closed validation."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone

from .errors import AuditValidationError

TIMESTAMP_FORMAT = "%Y-%m-%dT%H:%M:%SZ"
REQUIRED_FIELDS = ("timestamp", "actor", "action", "asset", "record_id")


def utc_now() -> str:
    return datetime.now(timezone.utc).strftime(TIMESTAMP_FORMAT)


def parse_timestamp(value: str) -> datetime:
    try:
        return datetime.strptime(value, TIMESTAMP_FORMAT).replace(tzinfo=timezone.utc)
    except (TypeError, ValueError) as exc:
        raise AuditValidationError("timestamp", f"expected format {TIMESTAMP_FORMAT}") from exc


@dataclass(frozen=True)
class AuditEvent:
    timestamp: str    # When (UTC)
    actor: str        # Who
    role: str         # Who
    department: str   # Who
    action: str       # How
    asset: str        # What
    record_id: str    # What — correlation key
    source_ip: str    # Where
    purpose: str      # Why
    result: str       # Result
    details: dict[str, str] = field(default_factory=dict)

    def validate(self) -> None:
        for name in REQUIRED_FIELDS:
            value = getattr(self, name)
            if not isinstance(value, str) or not value.strip():
                raise AuditValidationError(name, "must be a non-empty string")
        parse_timestamp(self.timestamp)
        if not isinstance(self.details, dict):
            raise AuditValidationError("details", "must be a dict")
        for key, value in self.details.items():
            if not isinstance(key, str) or not isinstance(value, str):
                raise AuditValidationError("details", "keys and values must be strings")

    def to_dict(self) -> dict:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict) -> "AuditEvent":
        return cls(**data)
```

- [ ] **Step 4: 테스트 통과 확인**

Run: `PY -m pytest audit-engine/tests/test_schema.py`
Expected: `13 passed`

- [ ] **Step 5: PROCESS.md 기록 + 커밋**

`PROCESS.md` 추가:
```markdown

### [P1-T2] schema.py
- `AuditEvent`(10필드 + `details`), `validate()`(필수값·UTC Z 타임스탬프·details 문자열 맵), `utc_now`, `parse_timestamp`.
- 테스트: `test_schema.py` 13 passed.
```

```bash
git add audit-engine/audit_engine/schema.py audit-engine/tests/test_schema.py PROCESS.md
git commit -m "feat(audit-engine): add AuditEvent schema with fail-closed validation"
```

---

### Task 3: `chain.py` — 증분 JSONL 해시체인

**Files:**
- Create: `audit-engine/audit_engine/chain.py`
- Test: `audit-engine/tests/test_chain.py`

**Interfaces:**
- Consumes: `errors.{ChainCorruptError, AuditStorageError}`
- Produces:
  - `GENESIS_HASH = "GENESIS"`, `HASH_ALGORITHMS = ("sha256", "sha512", "sha3_256")`
  - `canonical_json(obj) -> str`
  - `compute_entry_hash(entry: dict, algorithm: str) -> str`
  - `ChainEntry(seq, record, sealed, retention, previous_hash, entry_hash)` frozen; `.to_dict()`, `ChainEntry.from_dict(d)`
  - `ChainVerification(valid, entries_checked, failed_seq=None, reason=None)` frozen
  - `HashChain(path, algorithm="sha256")`; `HashChain.open(path, algorithm) -> HashChain` (전체 검증, 손상 시 `ChainCorruptError`); `.append(record, sealed, retention) -> ChainEntry`; `.verify() -> ChainVerification`; `.iter_entries() -> Iterator[ChainEntry]`; `.path` 속성

- [ ] **Step 1: 실패하는 테스트 작성**

`audit-engine/tests/test_chain.py`:
```python
import json

import pytest

from audit_engine.chain import GENESIS_HASH, ChainEntry, HashChain, canonical_json, compute_entry_hash
from audit_engine.errors import AuditStorageError, ChainCorruptError

RETENTION = {"retention_days": 365, "retention_until": "2027-09-01", "legal_basis": "test", "category": "test"}


def make_record(i: int) -> dict:
    return {"record_id": f"req-{i}", "actor": f"P-{i:016x}", "purpose": "hello"}


def fill(chain: HashChain, n: int) -> list[ChainEntry]:
    return [chain.append(make_record(i), None, RETENTION) for i in range(1, n + 1)]


def read_lines(path) -> list[dict]:
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]


def write_lines(path, rows: list[dict]) -> None:
    path.write_text("".join(canonical_json(row) + "\n" for row in rows), encoding="utf-8")


def test_canonical_json_is_sorted_compact_utf8():
    assert canonical_json({"b": 1, "a": "한글"}) == '{"a":"한글","b":1}'


def test_append_links_entries_and_verifies(tmp_path):
    chain = HashChain(tmp_path / "chain.jsonl")
    entries = fill(chain, 3)
    assert [e.seq for e in entries] == [1, 2, 3]
    assert entries[0].previous_hash == GENESIS_HASH
    assert entries[1].previous_hash == entries[0].entry_hash
    assert entries[2].previous_hash == entries[1].entry_hash
    assert entries[0].entry_hash == compute_entry_hash(entries[0].to_dict(), "sha256")
    result = chain.verify()
    assert result.valid and result.entries_checked == 3 and result.failed_seq is None


def test_open_resumes_from_existing_tail(tmp_path):
    path = tmp_path / "chain.jsonl"
    first = fill(HashChain(path), 2)
    reopened = HashChain.open(path)
    third = reopened.append(make_record(3), None, RETENTION)
    assert third.seq == 3 and third.previous_hash == first[1].entry_hash
    assert reopened.verify().valid


def test_tampered_record_detected_at_seq(tmp_path):
    path = tmp_path / "chain.jsonl"
    fill(HashChain(path), 3)
    rows = read_lines(path)
    rows[1]["record"]["purpose"] = "TAMPERED"
    write_lines(path, rows)
    result = HashChain(path).verify()
    assert (result.valid, result.failed_seq, result.reason) == (False, 2, "entry_hash_mismatch")


def test_deleted_middle_line_detected_as_seq_gap(tmp_path):
    path = tmp_path / "chain.jsonl"
    fill(HashChain(path), 3)
    rows = read_lines(path)
    del rows[1]
    write_lines(path, rows)
    result = HashChain(path).verify()
    assert (result.valid, result.failed_seq, result.reason) == (False, 3, "seq_gap")


def test_tampered_previous_hash_detected(tmp_path):
    path = tmp_path / "chain.jsonl"
    fill(HashChain(path), 2)
    rows = read_lines(path)
    rows[1]["previous_hash"] = "0" * 64
    write_lines(path, rows)
    result = HashChain(path).verify()
    assert (result.valid, result.failed_seq, result.reason) == (False, 2, "previous_hash_mismatch")


def test_malformed_line_detected(tmp_path):
    path = tmp_path / "chain.jsonl"
    fill(HashChain(path), 2)
    with path.open("a", encoding="utf-8") as fh:
        fh.write('{"seq": 3, "record": {}, "truncated')
    result = HashChain(path).verify()
    assert (result.valid, result.failed_seq, result.reason) == (False, 3, "malformed_line")


def test_open_refuses_corrupt_chain(tmp_path):
    path = tmp_path / "chain.jsonl"
    fill(HashChain(path), 2)
    rows = read_lines(path)
    rows[0]["record"]["purpose"] = "X"
    write_lines(path, rows)
    with pytest.raises(ChainCorruptError):
        HashChain.open(path)


def test_missing_file_is_empty_valid_chain(tmp_path):
    chain = HashChain.open(tmp_path / "nope.jsonl")
    assert chain.verify().valid and chain.verify().entries_checked == 0
    assert list(chain.iter_entries()) == []


def test_unwritable_path_raises_storage_error(tmp_path):
    blocked = tmp_path / "chain.jsonl"
    blocked.mkdir()  # a directory where the file should be
    with pytest.raises(AuditStorageError):
        HashChain(blocked).append(make_record(1), None, RETENTION)


def test_algorithm_allowlist(tmp_path):
    with pytest.raises(ValueError):
        HashChain(tmp_path / "c.jsonl", algorithm="md5")
    chain = HashChain(tmp_path / "c.jsonl", algorithm="sha3_256")
    entry = chain.append(make_record(1), {"alg": "AES-256-GCM", "nonce_b64": "AA==", "ciphertext_b64": "AA=="}, RETENTION)
    assert len(entry.entry_hash) == 64 and chain.verify().valid
```

- [ ] **Step 2: 테스트 실패 확인**

Run: `PY -m pytest audit-engine/tests/test_chain.py`
Expected: FAIL — `ModuleNotFoundError: No module named 'audit_engine.chain'`

- [ ] **Step 3: 구현**

`audit-engine/audit_engine/chain.py`:
```python
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
```

- [ ] **Step 4: 테스트 통과 확인**

Run: `PY -m pytest audit-engine/tests/test_chain.py`
Expected: `11 passed`

- [ ] **Step 5: PROCESS.md 기록 + 커밋**

`PROCESS.md` 추가:
```markdown

### [P1-T3] chain.py
- 증분 JSONL 해시체인: `append`(lock+fsync), `verify`(실패 seq/사유: previous_hash_mismatch·entry_hash_mismatch·seq_gap·malformed_line), `open`(손상 시 ChainCorruptError), OSError→AuditStorageError.
- 테스트: `test_chain.py` 11 passed (변조 4종 포함).
```

```bash
git add audit-engine/audit_engine/chain.py audit-engine/tests/test_chain.py PROCESS.md
git commit -m "feat(audit-engine): add incremental JSONL hash chain with debuggable verification"
```

---

### Task 4: `crypto.py` — AES-256-GCM 봉인 + KEK 래핑 KeyVault

**Files:**
- Create: `audit-engine/audit_engine/crypto.py`
- Test: `audit-engine/tests/test_crypto.py`

**Interfaces:**
- Consumes: `errors.{KeyNotFoundError, SealIntegrityError, AuditStorageError}`
- Produces:
  - `SEAL_ALGORITHM = "AES-256-GCM"`, `KEY_BYTES = 32`, `NONCE_BYTES = 12`
  - `generate_key() -> bytes` (32B)
  - `seal(plaintext: bytes, dek: bytes, aad: bytes) -> dict` → `{"alg","nonce_b64","ciphertext_b64"}`
  - `unseal(sealed: dict, dek: bytes, aad: bytes) -> bytes` (실패 → `SealIntegrityError`)
  - `KeyVault(path, kek: bytes)`: `.put(record_id, dek)`, `.get(record_id) -> bytes`, `.has(record_id) -> bool`, `.shred(record_id) -> bool`
  - `vault_record_ids(path) -> set[str]` (KEK 없이 id 목록만; 파일 없으면 빈 집합)

- [ ] **Step 1: 실패하는 테스트 작성**

`audit-engine/tests/test_crypto.py`:
```python
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
```

- [ ] **Step 2: 테스트 실패 확인**

Run: `PY -m pytest audit-engine/tests/test_crypto.py`
Expected: FAIL — `ModuleNotFoundError: No module named 'audit_engine.crypto'`

- [ ] **Step 3: 구현**

`audit-engine/audit_engine/crypto.py`:
```python
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

from .errors import AuditStorageError, KeyNotFoundError, SealIntegrityError

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


def vault_record_ids(path: str | os.PathLike[str]) -> set[str]:
    file = Path(path)
    if not file.exists():
        return set()
    try:
        return set(json.loads(file.read_text(encoding="utf-8")).keys())
    except OSError as exc:
        raise AuditStorageError(f"cannot read vault {file}: {exc.__class__.__name__}") from exc


class KeyVault:
    """JSON file {record_id: {nonce_b64, wrapped_b64}}; DEKs are wrapped with the KEK (AES-GCM, aad=record_id)."""

    def __init__(self, path: str | os.PathLike[str], kek: bytes) -> None:
        if len(kek) != KEY_BYTES:
            raise ValueError("KEK must be exactly 32 bytes")
        self._path = Path(path)
        self._kek = AESGCM(kek)
        self._lock = threading.Lock()

    def _load(self) -> dict:
        if not self._path.exists():
            return {}
        try:
            return json.loads(self._path.read_text(encoding="utf-8"))
        except OSError as exc:
            raise AuditStorageError(f"cannot read vault {self._path}: {exc.__class__.__name__}") from exc

    def _save(self, vault: dict) -> None:
        try:
            self._path.parent.mkdir(parents=True, exist_ok=True)
            fd, tmp_name = tempfile.mkstemp(dir=self._path.parent, prefix=".vault-", suffix=".tmp")
            with os.fdopen(fd, "w", encoding="utf-8") as fh:
                json.dump(vault, fh, indent=2, sort_keys=True)
                fh.flush()
                os.fsync(fh.fileno())
            os.replace(tmp_name, self._path)
        except OSError as exc:
            raise AuditStorageError(f"cannot write vault {self._path}: {exc.__class__.__name__}") from exc

    def put(self, record_id: str, dek: bytes) -> None:
        nonce = secrets.token_bytes(NONCE_BYTES)
        wrapped = self._kek.encrypt(nonce, dek, record_id.encode("utf-8"))
        with self._lock:
            vault = self._load()
            vault[record_id] = {"nonce_b64": _b64e(nonce), "wrapped_b64": _b64e(wrapped)}
            self._save(vault)

    def has(self, record_id: str) -> bool:
        with self._lock:
            return record_id in self._load()

    def get(self, record_id: str) -> bytes:
        with self._lock:
            entry = self._load().get(record_id)
        if entry is None:
            raise KeyNotFoundError(f"no data key for record {record_id!r} (never stored or shredded)")
        try:
            return self._kek.decrypt(_b64d(entry["nonce_b64"]), _b64d(entry["wrapped_b64"]), record_id.encode("utf-8"))
        except (InvalidTag, KeyError, ValueError, TypeError) as exc:
            raise SealIntegrityError(f"wrapped key for record {record_id!r} failed authentication") from exc

    def shred(self, record_id: str) -> bool:
        with self._lock:
            vault = self._load()
            if record_id not in vault:
                return False
            del vault[record_id]
            self._save(vault)
            return True
```

- [ ] **Step 4: 테스트 통과 확인**

Run: `PY -m pytest audit-engine/tests/test_crypto.py`
Expected: `11 passed`

- [ ] **Step 5: PROCESS.md 기록 + 커밋**

`PROCESS.md` 추가:
```markdown

### [P1-T4] crypto.py
- 3_5의 SHA-256 XOR 스트림 암호를 폐기하고 `cryptography` AESGCM으로 교체: `seal/unseal`(AAD=record_id), `KeyVault`(DEK를 KEK로 래핑, 원자적 쓰기, `shred`), `vault_record_ids`.
- 테스트: `test_crypto.py` 11 passed (AAD 불일치·키 오류·변조·잘못된 KEK 모두 실패 확인).
```

```bash
git add audit-engine/audit_engine/crypto.py audit-engine/tests/test_crypto.py PROCESS.md
git commit -m "feat(audit-engine): replace homemade XOR cipher with AES-256-GCM sealing and KEK-wrapped vault"
```

---

### Task 5: `masking.py` + `deidentification.py` — 3_5 이식 (secret 필수화)

**Files:**
- Create: `audit-engine/audit_engine/masking.py` (3_5 `src/audit_engine/masking.py` 그대로)
- Create: `audit-engine/audit_engine/deidentification.py` (3_5 이식, secret 기본값 제거)
- Test: `audit-engine/tests/test_masking.py`, `audit-engine/tests/test_deidentification.py`

**Interfaces:**
- Produces:
  - `masking.PATTERNS`, `masking.mask_text(text) -> tuple[str, list[dict[str,str]]]`, `masking.mask_record(value, key_name=None) -> tuple[Any, list[dict[str,str]]]`
  - `deidentification.pseudonymize_value(value, secret: bytes) -> str` (`"P-" + 16 hex`; 빈 secret → `ValueError`)
  - `deidentification.pseudonymize_record(record, identifier_fields=(...), *, secret: bytes) -> dict`
  - `deidentification.anonymize_record(record, remove_fields=(...)) -> dict`

- [ ] **Step 1: 실패하는 테스트 작성**

`audit-engine/tests/test_masking.py`:
```python
from audit_engine.masking import mask_record, mask_text

SAMPLE = "synthetic contact: sample.user@example.com, 010-1234-5678, RRN 900101-1234567, card 4111-1111-1111-1111"


def test_mask_text_masks_all_four_pii_types_and_reports_findings():
    masked, findings = mask_text(SAMPLE)
    assert "sample.user@example.com" not in masked
    assert "010-1234-5678" not in masked
    assert "900101-1234567" not in masked
    assert "4111-1111-1111-1111" not in masked
    assert {f["type"] for f in findings} == {"email", "phone", "rrn", "card"}
    assert "[EMAIL_MASKED]" in masked and "[CARD_MASKED]" in masked


def test_rescan_after_masking_finds_nothing():
    masked, _ = mask_text(SAMPLE)
    assert mask_text(masked)[1] == []


def test_mask_record_recurses_and_does_not_mutate_input():
    record = {"purpose": SAMPLE, "details": {"note": "mail me at a@b.io"}, "actor": "alice", "n": 3}
    protected, findings = mask_record(record)
    assert record["purpose"] == SAMPLE
    assert "example.com" not in protected["purpose"]
    assert protected["details"]["note"] == "mail me at [EMAIL_MASKED]"
    assert protected["actor"] == "alice" and protected["n"] == 3
    assert len(findings) == 5


def test_direct_field_labels_mask_whole_value():
    protected, findings = mask_record({"email": "anything-here"})
    assert protected == {"email": "[EMAIL_MASKED]"}
    assert findings == [{"type": "email", "value": "anything-here"}]
```

`audit-engine/tests/test_deidentification.py`:
```python
import re

import pytest

from audit_engine.deidentification import anonymize_record, pseudonymize_record, pseudonymize_value

SECRET = b"unit-test-secret-0123456789"


def test_pseudonym_is_deterministic_and_opaque():
    a = pseudonymize_value("alice", SECRET)
    assert a == pseudonymize_value("alice", SECRET)
    assert re.fullmatch(r"P-[0-9a-f]{16}", a)
    assert "alice" not in a


def test_pseudonym_depends_on_secret():
    assert pseudonymize_value("alice", SECRET) != pseudonymize_value("alice", b"another-secret-value-xyz")


def test_empty_secret_rejected():
    with pytest.raises(ValueError):
        pseudonymize_value("alice", b"")


def test_pseudonymize_record_replaces_only_configured_fields():
    out = pseudonymize_record({"actor": "alice", "role": "analyst"}, identifier_fields=("actor",), secret=SECRET)
    assert out["actor"].startswith("P-") and out["role"] == "analyst"


def test_pseudonymize_record_secret_is_keyword_only_and_required():
    with pytest.raises(TypeError):
        pseudonymize_record({"actor": "alice"}, ("actor",))  # no secret


def test_anonymize_record_removes_direct_identifiers_and_bands():
    out = anonymize_record({"name": "x", "age": 37, "purchase_amount": 200000, "keep": 1})
    assert out == {"keep": 1, "age_band": "30s", "purchase_band": "high"}
```

- [ ] **Step 2: 테스트 실패 확인**

Run: `PY -m pytest audit-engine/tests/test_masking.py audit-engine/tests/test_deidentification.py`
Expected: FAIL — `ModuleNotFoundError` (두 모듈 모두)

- [ ] **Step 3: 구현**

`audit-engine/audit_engine/masking.py` (3_5 원본 그대로):
```python
"""PII detection and irreversible log masking utilities."""

from __future__ import annotations

import re
from typing import Any


PATTERNS = {
    "email": re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}"),
    "phone": re.compile(r"01[0-9]-\d{3,4}-\d{4}"),
    "rrn": re.compile(r"\d{6}-\d{7}"),
    "card": re.compile(r"(?<!\d)(?:\d{4}[- ]?){3}\d{4}(?!\d)"),
}

DIRECT_FIELD_LABELS = {
    "name": "name",
    "email": "email",
    "phone": "phone",
    "address": "address",
}


def mask_value(label: str) -> str:
    return f"[{label.upper()}_MASKED]"


def mask_text(text: str) -> tuple[str, list[dict[str, str]]]:
    """Mask known PII patterns and return masked text plus findings."""
    masked = text
    findings: list[dict[str, str]] = []
    for label, pattern in PATTERNS.items():
        matches = pattern.findall(masked)
        for match in matches:
            findings.append({"type": label, "value": match})
        masked = pattern.sub(mask_value(label), masked)
    return masked, findings


def mask_record(value: Any, key_name: str | None = None) -> tuple[Any, list[dict[str, str]]]:
    """Recursively mask strings in dictionaries/lists without mutating input."""
    direct_label = DIRECT_FIELD_LABELS.get((key_name or "").lower())
    if direct_label and isinstance(value, str):
        return mask_value(direct_label), [{"type": direct_label, "value": value}]
    if isinstance(value, dict):
        output: dict[str, Any] = {}
        findings: list[dict[str, str]] = []
        for key, nested in value.items():
            output[key], nested_findings = mask_record(nested, key)
            findings.extend(nested_findings)
        return output, findings
    if isinstance(value, list):
        output = []
        findings = []
        for nested in value:
            masked, nested_findings = mask_record(nested, key_name)
            output.append(masked)
            findings.extend(nested_findings)
        return output, findings
    if isinstance(value, str):
        return mask_text(value)
    return value, []
```

`audit-engine/audit_engine/deidentification.py`:
```python
"""Audit data pseudonymization and anonymization helpers.

Pseudonyms are deterministic per secret: the same identifier maps to the same
pseudonym, and they cannot be reproduced without the secret. The secret has no
default on purpose — it must be injected from configuration (fail closed).
"""

from __future__ import annotations

import hashlib
import hmac
from typing import Any, Mapping


def pseudonymize_value(value: Any, secret: bytes) -> str:
    """Return a stable, non-reversible pseudonym for ``value`` under ``secret``."""
    if not secret:
        raise ValueError("pseudonymization secret must not be empty")
    digest = hmac.new(secret, str(value).encode("utf-8"), hashlib.sha256).hexdigest()
    return f"P-{digest[:16]}"


def pseudonymize_record(
    record: Mapping[str, Any],
    identifier_fields: tuple[str, ...] = ("name", "email", "customer_id", "user_id"),
    *,
    secret: bytes,
) -> dict[str, Any]:
    """Copy a record while replacing configured direct identifiers."""
    result = dict(record)
    for field in identifier_fields:
        if field in result and result[field] not in (None, ""):
            result[field] = pseudonymize_value(result[field], secret)
    return result


def anonymize_record(
    record: Mapping[str, Any],
    remove_fields: tuple[str, ...] = ("name", "email", "phone", "address", "customer_id", "user_id"),
) -> dict[str, Any]:
    """Remove direct identifiers and generalize common quasi-identifiers."""
    result = {key: value for key, value in record.items() if key not in remove_fields}
    if isinstance(result.get("age"), int):
        result["age_band"] = f"{(result.pop('age') // 10) * 10}s"
    if isinstance(result.get("purchase_amount"), (int, float)):
        amount = result.pop("purchase_amount")
        result["purchase_band"] = "high" if amount >= 150000 else "standard"
    return result
```

- [ ] **Step 4: 테스트 통과 확인**

Run: `PY -m pytest audit-engine/tests/test_masking.py audit-engine/tests/test_deidentification.py`
Expected: `10 passed`

- [ ] **Step 5: PROCESS.md 기록 + 커밋**

`PROCESS.md` 추가:
```markdown

### [P1-T5] masking.py / deidentification.py 이식
- `masking.py`는 3_5 원본 그대로. `deidentification.py`는 하드코딩 secret `b"audit-engine"` 제거, `secret` 필수(키워드 전용).
- 테스트: 10 passed (마스킹 후 재스캔 0, secret 의존성·필수성).
```

```bash
git add audit-engine/audit_engine/masking.py audit-engine/audit_engine/deidentification.py audit-engine/tests/test_masking.py audit-engine/tests/test_deidentification.py PROCESS.md
git commit -m "feat(audit-engine): port PII masking and pseudonymization; require injected secret"
```

---

### Task 6: `retention.py` + 보존 정책 JSON — fail-open 제거

**Files:**
- Create: `audit-engine/audit_engine/policies/retention_policy.json`
- Create: `audit-engine/audit_engine/retention.py`
- Test: `audit-engine/tests/test_retention.py`

**Interfaces:**
- Consumes: `schema.{AuditEvent, parse_timestamp}`, `errors.AuditValidationError`
- Produces:
  - `DEFAULT_POLICY_PATH: Path` (패키지 내 JSON)
  - `RetentionPolicy(path)`; `.for_event(event) -> dict` = `{"retention_days": int, "retention_until": "YYYY-MM-DD", "legal_basis": str, "category": str}`
  - `RetentionPolicy.is_expired(retention: dict, today: date) -> bool` (staticmethod)

- [ ] **Step 1: 정책 JSON 작성**

`audit-engine/audit_engine/policies/retention_policy.json`:
```json
{
  "_comment": "감사 로그 보관 기간 정책. action별 retention_days / category / legal_basis. 3_5 항목 유지 + rag-agent 액션 추가.",
  "default_policy": {
    "retention_days": 365,
    "category": "일반 감사 로그 (1년)",
    "legal_basis": "일반 내부 보안 정책"
  },
  "policies": {
    "auth_login": {"retention_days": 365, "category": "인증/접근 로그 (1년)", "legal_basis": "개인정보보호법 / ISMS-P 인증 기준"},
    "update_guardrail": {"retention_days": 365, "category": "보안 정책 변경 로그 (1년)", "legal_basis": "내부 정보보호 통제 지침"},
    "export_pii": {"retention_days": 730, "category": "개인정보 추출 로그 (2년)", "legal_basis": "개인정보보호법 시행령 제31조"},
    "grant_role": {"retention_days": 1095, "category": "권한 변경 로그 (3년)", "legal_basis": "정보보호 관리체계 안전성 확보 조치"},
    "bulk_download": {"retention_days": 1095, "category": "이상 패턴 로그 (3년)", "legal_basis": "침해 사고 포렌식 및 사후 조사"},
    "break_glass_access": {"retention_days": 1825, "category": "비상 관리자 접근 로그 (5년)", "legal_basis": "전자금융거래법 / SOC 2 Type II"},
    "delete_audit_logs": {"retention_days": 1825, "category": "로그 삭제 침해 로그 (5년)", "legal_basis": "형법 업무방해 / 보안 감사 규정"},
    "agent_query": {"retention_days": 365, "category": "AI 에이전트 질의 로그 (1년)", "legal_basis": "내부 AI 서비스 감사 지침"},
    "agent_query_blocked": {"retention_days": 1095, "category": "프롬프트 인젝션 차단 로그 (3년)", "legal_basis": "침해 시도 증적 보존"},
    "auth_denied": {"retention_days": 1095, "category": "인증 실패 로그 (3년)", "legal_basis": "ISMS-P 접근통제 증적"},
    "audit_shred": {"retention_days": 1825, "category": "감사 키 파기 로그 (5년)", "legal_basis": "개인정보 파기 기록 의무"},
    "audit_unseal": {"retention_days": 1825, "category": "감사 원문 열람 로그 (5년)", "legal_basis": "개인정보 열람 기록 의무"}
  }
}
```

- [ ] **Step 2: 실패하는 테스트 작성**

`audit-engine/tests/test_retention.py`:
```python
from datetime import date

import pytest

from audit_engine.errors import AuditValidationError
from audit_engine.retention import DEFAULT_POLICY_PATH, RetentionPolicy
from audit_engine.schema import AuditEvent


def make_event(action: str, timestamp: str = "2026-09-01T03:00:00Z") -> AuditEvent:
    return AuditEvent(timestamp, "alice", "analyst", "rag-users", action, "rag-agent/agent", "r1", "127.0.0.1", "-", "ok")


@pytest.fixture
def policy() -> RetentionPolicy:
    return RetentionPolicy(DEFAULT_POLICY_PATH)


@pytest.mark.parametrize("action,days,until", [
    ("agent_query", 365, "2027-09-01"),
    ("agent_query_blocked", 1095, "2029-08-31"),
    ("auth_denied", 1095, "2029-08-31"),
    ("audit_shred", 1825, "2031-08-31"),
    ("audit_unseal", 1825, "2031-08-31"),
    ("unknown_action", 365, "2027-09-01"),
])
def test_retention_days_and_until(policy, action, days, until):
    result = policy.for_event(make_event(action))
    assert result["retention_days"] == days
    assert result["retention_until"] == until
    assert result["legal_basis"] and result["category"]


def test_malformed_timestamp_raises_instead_of_using_now(policy):
    with pytest.raises(AuditValidationError):
        policy.for_event(make_event("agent_query", timestamp="2026/09/01"))


def test_is_expired():
    retention = {"retention_until": "2027-09-01"}
    assert RetentionPolicy.is_expired(retention, date(2027, 9, 2)) is True
    assert RetentionPolicy.is_expired(retention, date(2027, 9, 1)) is False
```

- [ ] **Step 3: 테스트 실패 확인**

Run: `PY -m pytest audit-engine/tests/test_retention.py`
Expected: FAIL — `ModuleNotFoundError: No module named 'audit_engine.retention'`

- [ ] **Step 4: 구현**

`audit-engine/audit_engine/retention.py`:
```python
"""Retention-period calculation from an external policy file. No silent fallbacks."""

from __future__ import annotations

import json
import os
from datetime import date, timedelta
from pathlib import Path

from .schema import AuditEvent, parse_timestamp

DEFAULT_POLICY_PATH = Path(__file__).parent / "policies" / "retention_policy.json"


class RetentionPolicy:
    def __init__(self, path: str | os.PathLike[str]) -> None:
        data = json.loads(Path(path).read_text(encoding="utf-8"))
        self._default = data["default_policy"]
        self._policies = data.get("policies", {})

    def for_event(self, event: AuditEvent) -> dict:
        policy = self._policies.get(event.action, self._default)
        days = int(policy["retention_days"])
        until = parse_timestamp(event.timestamp) + timedelta(days=days)   # raises AuditValidationError
        return {
            "retention_days": days,
            "retention_until": until.strftime("%Y-%m-%d"),
            "legal_basis": policy.get("legal_basis", self._default.get("legal_basis", "")),
            "category": policy.get("category", self._default.get("category", "")),
        }

    @staticmethod
    def is_expired(retention: dict, today: date) -> bool:
        return date.fromisoformat(retention["retention_until"]) < today
```

- [ ] **Step 5: 테스트 통과 확인**

Run: `PY -m pytest audit-engine/tests/test_retention.py`
Expected: `8 passed`

- [ ] **Step 6: PROCESS.md 기록 + 커밋**

`PROCESS.md` 추가:
```markdown

### [P1-T6] retention.py + 정책 JSON
- 3_5 정책 유지 + `agent_query`(1년)/`agent_query_blocked`·`auth_denied`(3년)/`audit_shred`·`audit_unseal`(5년) 추가. 타임스탬프 오류 시 `now()` 대체 제거 → 예외.
- 테스트: `test_retention.py` 8 passed.
```

```bash
git add audit-engine/audit_engine/retention.py audit-engine/audit_engine/policies/retention_policy.json audit-engine/tests/test_retention.py PROCESS.md
git commit -m "feat(audit-engine): add retention policy engine without fail-open timestamp fallback"
```

---

### Task 7: `config.py` — 환경변수 → AuditConfig (fail-closed)

**Files:**
- Create: `audit-engine/audit_engine/config.py`
- Test: `audit-engine/tests/test_config.py`

**Interfaces:**
- Consumes: `errors.AuditConfigError`, `chain.HASH_ALGORITHMS`, `retention.DEFAULT_POLICY_PATH`
- Produces:
  - `DEFAULT_CHAIN_PATH = "./audit-data/chain.jsonl"`, `DEFAULT_VAULT_PATH = "./audit-data/vault.json"`
  - `AuditConfig(pseudonym_secret: bytes, kek: bytes, chain_path: Path, vault_path: Path, policy_path: Path, hash_algorithm: str)` frozen, `repr`에 비밀값 없음
  - `AuditConfig.from_env(env: Mapping[str, str] | None = None) -> AuditConfig` (`env=None`이면 `os.environ`)

- [ ] **Step 1: 실패하는 테스트 작성**

`audit-engine/tests/test_config.py`:
```python
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
```

- [ ] **Step 2: 테스트 실패 확인**

Run: `PY -m pytest audit-engine/tests/test_config.py`
Expected: FAIL — `ModuleNotFoundError: No module named 'audit_engine.config'`

- [ ] **Step 3: 구현**

`audit-engine/audit_engine/config.py`:
```python
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
```

- [ ] **Step 4: 테스트 통과 확인**

Run: `PY -m pytest audit-engine/tests/test_config.py`
Expected: `10 passed`

- [ ] **Step 5: PROCESS.md 기록 + 커밋**

`PROCESS.md` 추가:
```markdown

### [P1-T7] config.py
- `AuditConfig.from_env`: `AUDIT_PSEUDONYM_SECRET`(≥16자)·`AUDIT_KEK_B64`(32B) 필수, 알고리즘 허용목록, 정책 파일 존재 검사. `repr`에 비밀값 미노출.
- 테스트: `test_config.py` 10 passed.
```

```bash
git add audit-engine/audit_engine/config.py audit-engine/tests/test_config.py PROCESS.md
git commit -m "feat(audit-engine): add fail-closed environment configuration"
```

---

### Task 8: `recorder.py` — AuditRecorder (Add-on 진입점) + 공개 API

**Files:**
- Create: `audit-engine/audit_engine/recorder.py`
- Modify: `audit-engine/audit_engine/__init__.py` (공개 API re-export)
- Test: `audit-engine/tests/test_recorder.py`

**Interfaces:**
- Consumes: `config.AuditConfig`, `chain.{HashChain, ChainEntry, canonical_json}`, `crypto.{KeyVault, generate_key, seal, unseal}`, `deidentification.pseudonymize_value`, `masking.mask_record`, `retention.RetentionPolicy`, `schema.AuditEvent`, `errors.*`
- Produces:
  - `AuditRecorder(config)`; `AuditRecorder.from_env(env=None)`; `.record(event, sensitive=None) -> ChainEntry`; `.unseal(entry) -> dict`; 속성 `.chain: HashChain`, `.vault: KeyVault`, `.policy: RetentionPolicy`, `.config: AuditConfig`
  - `recorder.FREE_TEXT_FIELDS = ("purpose", "details")`; `recorder.protect_record(event, pseudonym_secret) -> dict` (actor 가명화 + 자유 텍스트 필드만 마스킹); `recorder.residual_pii_count(record: dict) -> int` (CLI report와 테스트가 사용)
  - `audit_engine` 패키지 공개 API: `AuditEvent, utc_now, AuditRecorder, AuditConfig, HashChain, ChainEntry, ChainVerification, KeyVault, RetentionPolicy, mask_text, mask_record, pseudonymize_value, AuditError` 및 모든 예외

- [ ] **Step 1: 실패하는 테스트 작성**

`audit-engine/tests/test_recorder.py`:
```python
import base64
import json

import pytest

from audit_engine import AuditEvent, AuditRecorder
from audit_engine.config import AuditConfig
from audit_engine.crypto import KeyVault
from audit_engine.errors import AuditError, AuditStorageError, AuditValidationError, KeyNotFoundError, SealIntegrityError
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


def test_from_env_reads_process_environment(tmp_path, monkeypatch):
    for key, value in env_for(tmp_path).items():
        monkeypatch.setenv(key, value)
    assert isinstance(AuditRecorder.from_env().config, AuditConfig)


def test_vault_type(recorder):
    assert isinstance(recorder.vault, KeyVault)
```

- [ ] **Step 2: 테스트 실패 확인**

Run: `PY -m pytest audit-engine/tests/test_recorder.py`
Expected: FAIL — `ImportError: cannot import name 'AuditRecorder' from 'audit_engine'`

- [ ] **Step 3: 구현**

`audit-engine/audit_engine/recorder.py`:
```python
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

        sealed = None
        if sensitive is not None:
            if self._vault.has(event.record_id):
                raise AuditValidationError("record_id", "a data key already exists for this record_id")
            dek = generate_key()
            sealed = seal(canonical_json(sensitive).encode("utf-8"), dek, event.record_id.encode("utf-8"))
            self._vault.put(event.record_id, dek)

        retention = self._policy.for_event(event)
        return self._chain.append(protected, sealed, retention)

    def unseal(self, entry: ChainEntry) -> dict:
        """Recover the sealed payload of an entry. Raises KeyNotFoundError if the key was shredded."""
        if entry.sealed is None:
            raise SealIntegrityError("entry has no sealed payload")
        record_id = str(entry.record["record_id"])
        dek = self._vault.get(record_id)
        return json.loads(unseal(entry.sealed, dek, record_id.encode("utf-8")).decode("utf-8"))
```

`audit-engine/audit_engine/__init__.py` (전체 교체):
```python
"""audit_engine — tamper-evident 5W1H audit engine.

Public API:
    AuditRecorder.from_env().record(event, sensitive)   # add-on entry point
    HashChain / KeyVault / RetentionPolicy              # building blocks
    python -m audit_engine verify|report|shred|unseal|keygen
"""

from .chain import ChainEntry, ChainVerification, HashChain, canonical_json
from .config import AuditConfig
from .crypto import KeyVault, generate_key, seal, unseal
from .deidentification import anonymize_record, pseudonymize_record, pseudonymize_value
from .errors import (
    AuditConfigError,
    AuditError,
    AuditStorageError,
    AuditValidationError,
    ChainCorruptError,
    KeyNotFoundError,
    SealIntegrityError,
)
from .masking import mask_record, mask_text
from .recorder import AuditRecorder
from .retention import RetentionPolicy
from .schema import AuditEvent, utc_now

__version__ = "0.1.0"

__all__ = [
    "AuditConfig", "AuditConfigError", "AuditError", "AuditEvent", "AuditRecorder", "AuditStorageError",
    "AuditValidationError", "ChainCorruptError", "ChainEntry", "ChainVerification", "HashChain", "KeyNotFoundError",
    "KeyVault", "RetentionPolicy", "SealIntegrityError", "anonymize_record", "canonical_json", "generate_key",
    "mask_record", "mask_text", "pseudonymize_record", "pseudonymize_value", "seal", "unseal", "utc_now",
]
```

- [ ] **Step 4: 테스트 통과 확인 (전체)**

Run: `PY -m pytest audit-engine`
Expected: 모든 테스트 통과 (`test_recorder.py` 11 passed 포함, 누적 77 passed)

- [ ] **Step 5: PROCESS.md 기록 + 커밋**

`PROCESS.md` 추가:
```markdown

### [P1-T8] recorder.py + 공개 API
- `AuditRecorder.record`: validate → `protect_record`(actor 가명화 + purpose/details만 마스킹; 식별자·타임스탬프는 보존) → sensitive 봉인(중복 record_id 거부) → 보존 → chain.append. `unseal`로 조사용 복호화. `residual_pii_count`로 자유 텍스트 잔여 PII 0 확인.
- `__init__.py` 공개 API 정리.
- 테스트: audit-engine 전체 77 passed.
```

```bash
git add audit-engine/audit_engine/recorder.py audit-engine/audit_engine/__init__.py audit-engine/tests/test_recorder.py PROCESS.md
git commit -m "feat(audit-engine): add AuditRecorder facade and public API"
```

---

### Task 9: `cli.py` — verify / report / shred / unseal / keygen

**Files:**
- Create: `audit-engine/audit_engine/cli.py`, `audit-engine/audit_engine/__main__.py`
- Test: `audit-engine/tests/test_cli.py`

**Interfaces:**
- Consumes: `recorder.{AuditRecorder, residual_pii_count}`, `chain.HashChain`, `crypto.{generate_key, vault_record_ids}`, `retention.RetentionPolicy`, `schema.{AuditEvent, utc_now}`, `config.{DEFAULT_CHAIN_PATH, DEFAULT_VAULT_PATH}`, `errors.*`
- Produces:
  - `cli.main(argv: list[str] | None = None) -> int`
  - `cli.build_report(chain: HashChain, vault_path: Path, today: date) -> dict` (report 명령이 쓰는 순수 함수; rag-agent 계획에서는 사용하지 않음)
  - 콘솔: `python -m audit_engine <verify|report|shred|unseal|keygen>`

- [ ] **Step 1: 실패하는 테스트 작성**

`audit-engine/tests/test_cli.py`:
```python
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
```

- [ ] **Step 2: 테스트 실패 확인**

Run: `PY -m pytest audit-engine/tests/test_cli.py`
Expected: FAIL — `ModuleNotFoundError: No module named 'audit_engine.cli'`

- [ ] **Step 3: 구현**

`audit-engine/audit_engine/cli.py`:
```python
"""Operator CLI: python -m audit_engine verify|report|shred|unseal|keygen."""

from __future__ import annotations

import argparse
import base64
import json
import os
import sys
from collections import Counter
from dataclasses import asdict
from datetime import date
from pathlib import Path
from uuid import uuid4

from .chain import HASH_ALGORITHMS, HashChain
from .config import DEFAULT_CHAIN_PATH, DEFAULT_VAULT_PATH
from .crypto import generate_key, vault_record_ids
from .errors import AuditConfigError, AuditError, KeyNotFoundError, SealIntegrityError
from .recorder import AuditRecorder, residual_pii_count
from .retention import RetentionPolicy
from .schema import AuditEvent, utc_now


def _chain_from_args(args: argparse.Namespace) -> HashChain:
    algorithm = os.environ.get("AUDIT_HASH_ALGORITHM", "sha256")
    if algorithm not in HASH_ALGORITHMS:
        raise AuditConfigError(f"AUDIT_HASH_ALGORITHM must be one of {HASH_ALGORITHMS}")
    return HashChain(args.chain or os.environ.get("AUDIT_CHAIN_PATH", DEFAULT_CHAIN_PATH), algorithm)


def _vault_path_from_args(args: argparse.Namespace) -> Path:
    return Path(getattr(args, "vault", None) or os.environ.get("AUDIT_VAULT_PATH", DEFAULT_VAULT_PATH))


def _operator_event(action: str, actor: str, purpose: str, result: str, details: dict[str, str]) -> AuditEvent:
    return AuditEvent(
        timestamp=utc_now(), actor=actor, role="operator", department="audit", action=action,
        asset="audit-engine/vault", record_id=str(uuid4()), source_ip="cli",
        purpose=purpose[:200] or "-", result=result, details=details,
    )


def build_report(chain: HashChain, vault_path: Path, today: date) -> dict:
    verification = chain.verify()
    report: dict = {
        "chain_path": str(chain.path),
        "generated_on": today.isoformat(),
        "verification": asdict(verification),
        "entries": 0,
        "anomalies": [] if verification.valid else ["chain_corrupt"],
    }
    if not verification.valid:
        return report
    entries = list(chain.iter_entries())
    vault_ids = vault_record_ids(vault_path)
    sealed = [e for e in entries if e.sealed is not None]
    expired = [e.record["record_id"] for e in entries if RetentionPolicy.is_expired(e.retention, today)]
    residual = sum(residual_pii_count(e.record) for e in entries)
    report.update({
        "entries": len(entries),
        "by_action": dict(Counter(e.record.get("action", "?") for e in entries)),
        "by_result": dict(Counter(e.record.get("result", "?") for e in entries)),
        "expired_count": len(expired),
        "expired_record_ids": expired,
        "sealed_count": len(sealed),
        "shredded_count": sum(1 for e in sealed if e.record["record_id"] not in vault_ids),
        "residual_plaintext_pii": residual,
    })
    if residual:
        report["anomalies"].append("residual_plaintext_pii")
    return report


def cmd_verify(args: argparse.Namespace) -> int:
    result = _chain_from_args(args).verify()
    print(json.dumps(asdict(result)))
    return 0 if result.valid else 1


def cmd_report(args: argparse.Namespace) -> int:
    report = build_report(_chain_from_args(args), _vault_path_from_args(args), date.today())
    valid = report["verification"]["valid"]
    print(f"chain: {'PASS' if valid else 'FAIL'} ({report['verification']})")
    print(f"entries: {report['entries']}")
    if valid:
        print(f"by_action: {report['by_action']}")
        print(f"by_result: {report['by_result']}")
        print(f"expired: {report['expired_count']}  sealed: {report['sealed_count']}  shredded: {report['shredded_count']}")
        print(f"residual_plaintext_pii: {report['residual_plaintext_pii']}")
    print(f"anomalies: {report['anomalies']}")
    if args.out:
        Path(args.out).write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")
    return 0 if not report["anomalies"] else 1


def cmd_shred(args: argparse.Namespace) -> int:
    recorder = AuditRecorder.from_env()
    if args.record_id:
        targets = [args.record_id]
        mode = "record_id"
    else:
        today = date.today()
        live = vault_record_ids(recorder.config.vault_path)
        targets = [
            e.record["record_id"] for e in recorder.chain.iter_entries()
            if e.sealed is not None and e.record["record_id"] in live and RetentionPolicy.is_expired(e.retention, today)
        ]
        mode = "expired"
    shredded = [rid for rid in targets if recorder.vault.shred(rid)]
    recorder.record(_operator_event(
        "audit_shred", args.actor, ",".join(targets), f"shredded:{len(shredded)}",
        {"mode": mode, "requested": str(len(targets)), "shredded": str(len(shredded))},
    ))
    print(json.dumps({"requested": targets, "shredded": shredded}))
    return 0 if shredded else 1


def cmd_unseal(args: argparse.Namespace) -> int:
    recorder = AuditRecorder.from_env()
    entry = next((e for e in recorder.chain.iter_entries() if e.record.get("record_id") == args.record_id), None)
    if entry is None:
        print(f"record {args.record_id!r} not found in chain", file=sys.stderr)
        return 1
    try:
        payload = recorder.unseal(entry)
    except (KeyNotFoundError, SealIntegrityError) as exc:
        recorder.record(_operator_event("audit_unseal", args.actor, args.record_id,
                                        f"denied:{exc.__class__.__name__}", {"target": args.record_id}))
        print(f"unseal denied: {exc}", file=sys.stderr)
        return 1
    recorder.record(_operator_event("audit_unseal", args.actor, args.record_id, "unsealed", {"target": args.record_id}))
    print(json.dumps(payload, ensure_ascii=False, indent=2))
    return 0


def cmd_keygen(args: argparse.Namespace) -> int:
    print(base64.b64encode(generate_key()).decode("ascii"))
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="audit_engine", description="Tamper-evident audit chain operator CLI")
    sub = parser.add_subparsers(dest="command", required=True)

    p = sub.add_parser("verify", help="verify the whole hash chain")
    p.add_argument("--chain", help="chain path (default: AUDIT_CHAIN_PATH)")
    p.set_defaults(func=cmd_verify)

    p = sub.add_parser("report", help="summarize the chain: actions, results, expiry, sealing, residual PII")
    p.add_argument("--chain")
    p.add_argument("--vault", help="vault path (default: AUDIT_VAULT_PATH)")
    p.add_argument("--out", help="write full JSON report here")
    p.set_defaults(func=cmd_report)

    p = sub.add_parser("shred", help="destroy data keys (crypto-shredding); audited")
    group = p.add_mutually_exclusive_group(required=True)
    group.add_argument("--record-id")
    group.add_argument("--expired", action="store_true", help="shred every sealed entry past its retention_until")
    p.add_argument("--actor", required=True, help="operator identity recorded in the audit_shred event")
    p.set_defaults(func=cmd_shred)

    p = sub.add_parser("unseal", help="decrypt one sealed payload for investigation; audited")
    p.add_argument("--record-id", required=True)
    p.add_argument("--actor", required=True)
    p.set_defaults(func=cmd_unseal)

    p = sub.add_parser("keygen", help="print a fresh 32-byte base64 KEK for AUDIT_KEK_B64")
    p.set_defaults(func=cmd_keygen)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        return args.func(args)
    except AuditError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
```

`audit-engine/audit_engine/__main__.py`:
```python
import sys

from .cli import main

sys.exit(main())
```

- [ ] **Step 4: 테스트 통과 확인 (전체)**

Run: `PY -m pytest audit-engine`
Expected: 모든 테스트 통과 (`test_cli.py` 9 passed 포함, 누적 86 passed)

- [ ] **Step 5: 수동 스모크**

```bash
PY -m audit_engine keygen           # 44자 base64 출력
PY -m audit_engine verify --chain audit-engine/tests/nonexistent.jsonl   # {"valid": true, "entries_checked": 0, ...} exit 0
```

- [ ] **Step 6: PROCESS.md 기록 + 커밋**

`PROCESS.md` 추가:
```markdown

### [P1-T9] cli.py
- `verify`(실패 seq/사유 JSON), `report`(집계·만료·봉인/파기·잔여 PII 재스캔·이상 목록, `--out`), `shred --record-id|--expired --actor`, `unseal --record-id --actor`, `keygen`. shred/unseal은 `audit_shred`/`audit_unseal` 이벤트로 체인에 기록됨(파기 후 기록 순서 — 기록 실패 시 stderr에 error, exit 1).
- 테스트: audit-engine 전체 86 passed. audit-engine 계획 완료.
```

```bash
git add audit-engine/audit_engine/cli.py audit-engine/audit_engine/__main__.py audit-engine/tests/test_cli.py PROCESS.md
git commit -m "feat(audit-engine): add operator CLI (verify/report/shred/unseal/keygen)"
```

---

## 완료 기준 (Plan 1)

- `PY -m pytest audit-engine` 전부 통과 (86 tests).
- `PY -c "import audit_engine as a; print(a.__version__, a.AuditRecorder)"` 동작.
- `ch3/3_5` 원본 무변경 (`git -C ../3_5 status`는 해당 없음 — 그 폴더는 git 저장소가 아니므로 파일 mtime으로 확인).
- `PROCESS.md`에 `[P1-T1]`~`[P1-T9]` 기록.
- 다음: `docs/superpowers/plans/2026-09-01-rag-agent.md` 실행.

