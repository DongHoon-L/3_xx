"""Cross-process exclusive advisory lock on a dedicated `<target>.lock` file.

The chain and the vault are read-modify-write resources that the service process and the
operator CLI touch at the same time, so an in-process `threading.Lock` is not enough.
Both branches use the non-blocking primitive inside one deadline loop so that `timeout_s`
means the same thing everywhere and a stuck holder fails closed instead of hanging forever.
"""

from __future__ import annotations

import os
import time
from contextlib import contextmanager
from pathlib import Path
from typing import Iterator

from .errors import AuditStorageError

try:  # POSIX
    import fcntl
except ImportError:  # pragma: no cover - exercised on Windows only
    fcntl = None  # type: ignore[assignment]

try:  # Windows
    import msvcrt
except ImportError:  # pragma: no cover - exercised on POSIX only
    msvcrt = None  # type: ignore[assignment]

DEFAULT_TIMEOUT_S = 10.0
RETRY_INTERVAL_S = 0.05
LOCK_BYTES = 1


def lock_path_for(target: str | os.PathLike[str]) -> Path:
    """The lock file that guards `target` (never the target itself: locking must not truncate data)."""
    path = Path(target)
    return path.with_suffix(path.suffix + ".lock")


def _try_acquire(fd: int) -> None:
    if msvcrt is not None:
        msvcrt.locking(fd, msvcrt.LK_NBLCK, LOCK_BYTES)
    else:
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)


def _release(fd: int) -> None:
    if msvcrt is not None:
        os.lseek(fd, 0, os.SEEK_SET)
        msvcrt.locking(fd, msvcrt.LK_UNLCK, LOCK_BYTES)
    else:
        fcntl.flock(fd, fcntl.LOCK_UN)


@contextmanager
def exclusive_lock(lock_path: str | os.PathLike[str], timeout_s: float = DEFAULT_TIMEOUT_S) -> Iterator[None]:
    """Hold an OS-level exclusive lock on `lock_path`. Times out as AuditStorageError."""
    path = Path(lock_path)
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        fd = os.open(str(path), os.O_RDWR | os.O_CREAT, 0o600)
    except OSError as exc:
        raise AuditStorageError(f"cannot open lock file {path}: {exc.__class__.__name__}") from exc
    try:
        deadline = time.monotonic() + timeout_s
        while True:
            try:
                _try_acquire(fd)
                break
            except OSError as exc:
                if time.monotonic() >= deadline:
                    raise AuditStorageError(f"lock timeout after {timeout_s}s waiting for {path}") from exc
                time.sleep(RETRY_INTERVAL_S)
        try:
            yield
        finally:
            try:
                _release(fd)
            except OSError as exc:  # the handle is closed below either way
                raise AuditStorageError(f"cannot release lock {path}: {exc.__class__.__name__}") from exc
    finally:
        os.close(fd)
