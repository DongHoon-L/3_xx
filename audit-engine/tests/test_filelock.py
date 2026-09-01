import pytest

from audit_engine.errors import AuditStorageError
from audit_engine.filelock import exclusive_lock, lock_path_for


def test_lock_path_is_the_target_plus_suffix(tmp_path):
    assert lock_path_for(tmp_path / "chain.jsonl") == tmp_path / "chain.jsonl.lock"
    assert lock_path_for(tmp_path / "vault.json") == tmp_path / "vault.json.lock"
    assert lock_path_for(tmp_path / "noext") == tmp_path / "noext.lock"


def test_lock_is_acquired_and_released(tmp_path):
    path = tmp_path / "c.jsonl.lock"
    with exclusive_lock(path):
        assert path.exists()
    with exclusive_lock(path):  # released by the first block, so this must not block
        pass


def test_second_holder_times_out_with_storage_error(tmp_path):
    path = tmp_path / "c.jsonl.lock"
    with exclusive_lock(path):
        with pytest.raises(AuditStorageError) as exc:
            with exclusive_lock(path, timeout_s=0.2):
                pass
    assert "lock timeout" in str(exc.value)


def test_lock_is_released_when_the_body_raises(tmp_path):
    path = tmp_path / "c.jsonl.lock"
    with pytest.raises(ZeroDivisionError):
        with exclusive_lock(path):
            1 / 0
    with exclusive_lock(path, timeout_s=0.2):  # would time out if the lock leaked
        pass


def test_unusable_lock_path_raises_storage_error(tmp_path):
    blocked = tmp_path / "c.jsonl.lock"
    blocked.mkdir()  # a directory where the lock file should be
    with pytest.raises(AuditStorageError):
        with exclusive_lock(blocked):
            pass
