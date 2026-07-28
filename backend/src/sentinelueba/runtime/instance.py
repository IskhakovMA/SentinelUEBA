from __future__ import annotations

import hashlib
import os
from dataclasses import dataclass
from pathlib import Path
from types import TracebackType

from sentinelueba.runtime.control import RuntimeStatus, read_status


class InstanceAlreadyRunningError(RuntimeError):
    def __init__(self, status: RuntimeStatus | None) -> None:
        super().__init__("SentinelUEBA host is already running for this runtime root")
        self.status = status


@dataclass
class SingleInstanceLock:
    data_root: Path
    runtime_dir: Path
    status_path: Path
    _fd: int | None = None
    _mutex_handle: object | None = None

    def __enter__(self) -> SingleInstanceLock:
        self.runtime_dir.mkdir(parents=True, exist_ok=True)
        if os.name == "nt" and self._try_windows_mutex():
            return self
        self._try_file_lock()
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        if self._fd is not None:
            try:
                os.close(self._fd)
            finally:
                self._fd = None
            (self.runtime_dir / "host.lock").unlink(missing_ok=True)
        if self._mutex_handle is not None:
            try:
                import win32api
                import win32con
                import win32event

                win32event.ReleaseMutex(self._mutex_handle)
                win32api.CloseHandle(self._mutex_handle)
                _ = win32con.INFINITE
            except Exception:
                pass
            self._mutex_handle = None

    def _try_windows_mutex(self) -> bool:
        try:
            import win32api
            import win32event
        except ImportError:
            return False
        name = mutex_name(self.data_root)
        handle = win32event.CreateMutex(None, False, name)
        if win32api.GetLastError() != 0:
            raise InstanceAlreadyRunningError(read_status(self.status_path))
        self._mutex_handle = handle
        return True

    def _try_file_lock(self) -> None:
        lock_path = self.runtime_dir / "host.lock"
        flags = os.O_CREAT | os.O_EXCL | os.O_RDWR
        try:
            self._fd = os.open(lock_path, flags, 0o600)
        except FileExistsError as exc:
            status = read_status(self.status_path)
            if status is not None and not process_alive(status.pid):
                lock_path.unlink(missing_ok=True)
                self._fd = os.open(lock_path, flags, 0o600)
                return
            raise InstanceAlreadyRunningError(status) from exc


def mutex_name(data_root: Path) -> str:
    normalized = str(data_root.resolve()).casefold().encode("utf-8")
    return f"Local\\SentinelUEBA-{hashlib.sha256(normalized).hexdigest()[:32]}"


def process_alive(pid: int) -> bool:
    if pid <= 0:
        return False
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    return True
