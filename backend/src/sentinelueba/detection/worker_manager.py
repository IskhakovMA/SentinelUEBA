from __future__ import annotations

import threading
from dataclasses import dataclass
from pathlib import Path
from uuid import uuid4

from sentinelueba.detection.service import DetectionService
from sentinelueba.storage.sqlite import SQLiteStorage


class DetectionWorkerAlreadyRunningError(ValueError):
    pass


@dataclass
class _WorkerHandle:
    worker_key: str
    owner_id: str
    stop_event: threading.Event
    thread: threading.Thread


class DetectionWorkerManager:
    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._handles: dict[str, _WorkerHandle] = {}

    def start(
        self,
        *,
        database_path: Path,
        data_dir: Path,
        model_dir: Path,
        dataset_kind: str,
        interval_seconds: int,
        max_windows: int | None = 256,
    ) -> dict[str, object]:
        worker_key = self._worker_key(dataset_kind, None)
        manager_key = self._manager_key(database_path, worker_key)
        owner_id = f"owner-{uuid4().hex}"
        stop_event = threading.Event()

        with self._lock:
            existing = self._handles.get(manager_key)
            if existing is not None and existing.thread.is_alive():
                raise DetectionWorkerAlreadyRunningError("detection worker is already running")

            def run() -> None:
                service = DetectionService(
                    SQLiteStorage(database_path),
                    data_dir,
                    model_dir,
                )
                try:
                    service.worker_run_foreground(
                        dataset_kind=dataset_kind,
                        max_windows=max_windows,
                        interval_seconds=interval_seconds,
                        single_cycle=False,
                        stop_event=stop_event,
                        owner_id=owner_id,
                    )
                finally:
                    with self._lock:
                        handle = self._handles.get(manager_key)
                        if handle is not None and handle.owner_id == owner_id:
                            self._handles.pop(manager_key, None)

            thread = threading.Thread(
                target=run,
                name=f"sentinelueba-detection-{dataset_kind}",
                daemon=True,
            )
            self._handles[manager_key] = _WorkerHandle(
                worker_key=worker_key,
                owner_id=owner_id,
                stop_event=stop_event,
                thread=thread,
            )
            thread.start()

        return self.status(
            database_path=database_path,
            data_dir=data_dir,
            model_dir=model_dir,
            dataset_kind=dataset_kind,
        )

    def stop(
        self,
        *,
        database_path: Path,
        data_dir: Path,
        model_dir: Path,
        dataset_kind: str | None,
        confirm: bool,
        timeout_seconds: float = 10.0,
    ) -> dict[str, object]:
        service = DetectionService(SQLiteStorage(database_path), data_dir, model_dir)
        status = service.worker_stop(confirm=confirm)
        manager_key = (
            self._manager_key(database_path, self._worker_key(dataset_kind, None))
            if dataset_kind is not None
            else None
        )
        with self._lock:
            handles = [
                (key, handle)
                for key, handle in self._handles.items()
                if (
                    key == manager_key
                    if manager_key is not None
                    else key.startswith(f"{database_path.resolve()}|")
                )
            ]
        for key, handle in handles:
            handle.stop_event.set()
            handle.thread.join(timeout=timeout_seconds)
            if not handle.thread.is_alive():
                with self._lock:
                    self._handles.pop(key, None)
        return status

    def status(
        self,
        *,
        database_path: Path,
        data_dir: Path,
        model_dir: Path,
        dataset_kind: str = "synthetic",
    ) -> dict[str, object]:
        service = DetectionService(SQLiteStorage(database_path), data_dir, model_dir)
        status = service.worker_status()
        worker_key = self._worker_key(dataset_kind, None)
        manager_key = self._manager_key(database_path, worker_key)
        with self._lock:
            handle = self._handles.get(manager_key)
            alive = handle is not None and handle.thread.is_alive()
        status["process_running"] = alive
        return status

    def shutdown_process(
        self,
        *,
        database_path: Path,
        data_dir: Path,
        model_dir: Path,
    ) -> None:
        with self._lock:
            handles = list(self._handles.items())
        service = DetectionService(SQLiteStorage(database_path), data_dir, model_dir)
        for manager_key, handle in handles:
            if not manager_key.startswith(f"{database_path.resolve()}|"):
                continue
            handle.stop_event.set()
            handle.thread.join(timeout=10.0)
            service.worker_stop(confirm=True)

    def _manager_key(self, database_path: Path, worker_key: str) -> str:
        return f"{database_path.resolve()}|{worker_key}"

    def _worker_key(self, dataset_kind: str, profile: str | None) -> str:
        return "|".join(["stage4", dataset_kind, profile or "*"])


_MANAGER = DetectionWorkerManager()


def get_detection_worker_manager() -> DetectionWorkerManager:
    return _MANAGER
