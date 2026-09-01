import json

import pytest

from audit_engine.chain import (
    GENESIS_HASH,
    ChainEntry,
    ChainVerification,
    HashChain,
    canonical_json,
    compute_entry_hash,
)
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


def test_two_instances_appending_alternately_stay_linked(tmp_path):
    """Second writer (e.g. the operator CLI): each append resyncs from the on-disk tail."""
    path = tmp_path / "chain.jsonl"
    a, b = HashChain(path), HashChain(path)
    entries = [a.append(make_record(1), None, RETENTION), b.append(make_record(2), None, RETENTION),
               a.append(make_record(3), None, RETENTION), b.append(make_record(4), None, RETENTION)]
    assert [e.seq for e in entries] == [1, 2, 3, 4]
    assert HashChain(path).verify() == ChainVerification(True, 4)
    assert len(read_lines(path)) == 4


def test_append_on_tampered_interior_refuses_and_writes_nothing(tmp_path):
    path = tmp_path / "chain.jsonl"
    fill(HashChain(path), 3)
    rows = read_lines(path)
    rows[1]["record"]["purpose"] = "TAMPERED"
    write_lines(path, rows)
    stale = HashChain(path)  # never opened: its (seq, hash) do not match the tail, so it must re-walk
    with pytest.raises(ChainCorruptError):
        stale.append(make_record(4), None, RETENTION)
    assert len(read_lines(path)) == 3


def test_append_after_the_tail_was_tampered_refuses(tmp_path):
    path = tmp_path / "chain.jsonl"
    chain = HashChain(path)
    fill(chain, 2)
    rows = read_lines(path)
    rows[-1]["record"]["purpose"] = "TAMPERED"
    write_lines(path, rows)
    with pytest.raises(ChainCorruptError):
        chain.append(make_record(3), None, RETENTION)
    assert len(read_lines(path)) == 2


def test_append_resyncs_after_the_file_was_replaced_by_a_shorter_valid_chain(tmp_path):
    path = tmp_path / "chain.jsonl"
    chain = HashChain(path)
    fill(chain, 3)
    write_lines(path, read_lines(path)[:1])  # a valid 1-entry chain: resync, do not fork
    fourth = chain.append(make_record(4), None, RETENTION)
    assert fourth.seq == 2 and chain.verify().valid


def test_algorithm_allowlist(tmp_path):
    with pytest.raises(ValueError):
        HashChain(tmp_path / "c.jsonl", algorithm="md5")
    chain = HashChain(tmp_path / "c.jsonl", algorithm="sha3_256")
    entry = chain.append(make_record(1), {"alg": "AES-256-GCM", "nonce_b64": "AA==", "ciphertext_b64": "AA=="}, RETENTION)
    assert len(entry.entry_hash) == 64 and chain.verify().valid
