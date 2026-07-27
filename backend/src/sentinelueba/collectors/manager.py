from __future__ import annotations

import threading
from collections import Counter
from datetime import UTC, datetime, timedelta
from typing import Any
from uuid import uuid4

from sentinelueba import __version__
from sentinelueba.collectors.base import CollectorPollResult, CollectorStatus, TelemetryCollector
from sentinelueba.collectors.identity import IdentityProvider
from sentinelueba.collectors.network import NetworkCollector
from sentinelueba.collectors.process import ProcessCollector
from sentinelueba.collectors.system_metrics import SystemMetricsCollector
from sentinelueba.collectors.windows_auth import WindowsAuthCollector
from sentinelueba.config import Settings
from sentinelueba.normalization.normalizer import normalize_events
from sentinelueba.storage.sqlite import SQLiteStorage


class CollectionAlreadyRunningError(RuntimeError):
    pass


class NoAvailableCollectorsError(RuntimeError):
    def __init__(self, capabilities: list[dict[str, Any]]) -> None:
        super().__init__("no selected collectors are available")
        self.capabilities = capabilities


class CollectionStopTimeoutError(RuntimeError):
    pass


class CollectorManager:
    def __init__(self, settings: Settings, storage: SQLiteStorage | None = None) -> None:
        self.settings = settings
        self.storage = storage or SQLiteStorage(settings.database_path)
        self.storage.initialize()
        self.storage.mark_stale_running_sessions()
        self._lock = threading.Lock()
        self._stop_event = threading.Event()
        self._thread: threading.Thread | None = None
        self._session_id: str | None = None
        self._collectors: list[TelemetryCollector] = []
        self._status: dict[str, dict[str, Any]] = {}
        self._counters: Counter[str] = Counter()
        self._errors: list[str] = []

    def build_collectors(self, enabled: list[str] | None = None) -> list[TelemetryCollector]:
        user_id, host_id = IdentityProvider(
            self.settings.data_dir,
            mode=self.settings.identity_mode,
        ).user_host()
        auth_cursor = self.storage.get_collector_cursor(WindowsAuthCollector.collector_id)
        collectors: list[TelemetryCollector] = [
            ProcessCollector(user_id, host_id),
            NetworkCollector(user_id, host_id),
            SystemMetricsCollector(user_id, host_id),
            WindowsAuthCollector(user_id, host_id, auth_cursor),
        ]
        if enabled:
            enabled_set = set(enabled)
            collectors = [
                collector
                for collector in collectors
                if collector.collector_id in enabled_set
            ]
        return collectors

    def capabilities(self) -> list[dict[str, Any]]:
        return [
            capability.__dict__
            for capability in (c.check_availability() for c in self.build_collectors())
        ]

    def start(
        self,
        *,
        duration_seconds: int | None = None,
        interval_seconds: float = 5.0,
        enabled_collectors: list[str] | None = None,
        collection_mode: str = "real",
    ) -> dict[str, Any]:
        with self._lock:
            if self._thread is not None and self._thread.is_alive():
                raise CollectionAlreadyRunningError("collection is already running")
            self._stop_event.clear()
            self._counters = Counter()
            self._errors = []
            self._status = {}
            self._collectors = self.build_collectors(enabled_collectors)
            capabilities = [
                collector.check_availability().__dict__
                for collector in self._collectors
            ]
            available = [
                collector
                for collector in self._collectors
                if collector.check_availability().status == CollectorStatus.AVAILABLE
            ]
            if not available:
                raise NoAvailableCollectorsError(capabilities)
            self._collectors = available
            self._session_id = str(uuid4())
            self.storage.start_session(
                self._session_id,
                collection_mode,
                [collector.collector_id for collector in self._collectors],
                __version__,
            )
            self._thread = threading.Thread(
                target=self._run,
                args=(duration_seconds, interval_seconds),
                daemon=True,
            )
            self._thread.start()
            return self.status()

    def stop(self) -> dict[str, Any]:
        self._stop_event.set()
        thread = self._thread
        if thread is not None:
            thread.join(timeout=10)
            if thread.is_alive():
                raise CollectionStopTimeoutError("collection thread did not stop within timeout")
        return self.status()

    def status(self) -> dict[str, Any]:
        running = self._thread is not None and self._thread.is_alive()
        return {
            "running": running,
            "session_id": self._session_id,
            "collectors": self._status,
            "counters": dict(self._counters),
            "errors": self._errors[-20:],
            "progress": self.storage.collection_progress(),
        }

    def sessions(self) -> list[dict[str, Any]]:
        return self.storage.list_sessions()

    def progress(self) -> dict[str, Any]:
        return self.storage.collection_progress()

    def _run(self, duration_seconds: int | None, interval_seconds: float) -> None:
        deadline = (
            datetime.now(UTC) + timedelta(seconds=duration_seconds)
            if duration_seconds is not None
            else None
        )
        status = "completed"
        try:
            for collector in self._collectors:
                try:
                    collector.start()
                    self._status[collector.collector_id] = collector.health().__dict__
                except Exception as exc:  # noqa: BLE001
                    self._errors.append(f"{collector.collector_id}: {type(exc).__name__}")
            while not self._stop_event.is_set():
                if deadline is not None and datetime.now(UTC) >= deadline:
                    break
                successful = self._collect_once(interval_seconds)
                if self._session_id is not None:
                    self.storage.update_session_heartbeat(
                        self._session_id,
                        dict(self._counters),
                        self._errors,
                        successful,
                    )
                wait_seconds = max(0.1, interval_seconds)
                if deadline is not None:
                    remaining = (deadline - datetime.now(UTC)).total_seconds()
                    wait_seconds = min(wait_seconds, max(0.0, remaining))
                if self._stop_event.wait(wait_seconds):
                    break
        except Exception as exc:  # noqa: BLE001
            status = "error"
            self._errors.append(type(exc).__name__)
        finally:
            for collector in self._collectors:
                try:
                    collector.stop()
                except Exception as exc:  # noqa: BLE001
                    self._errors.append(f"{collector.collector_id}: {type(exc).__name__}")
                if hasattr(collector, "cursor"):
                    cursor = collector.cursor
                    if isinstance(cursor, dict):
                        self.storage.upsert_collector_state(
                            collector.collector_id,
                            "stopped",
                            cursor,
                            None,
                        )
            if self._stop_event.is_set():
                status = "stopped"
            if self._session_id is not None:
                self.storage.finish_session(
                    self._session_id,
                    status,
                    dict(self._counters),
                    self._errors,
                )

    def _collect_once(self, interval_seconds: float) -> bool:
        any_success = False
        for collector in self._collectors:
            observed_at = datetime.now(UTC)
            try:
                poll = getattr(collector, "poll", None)
                poll_result = (
                    poll()
                    if callable(poll)
                    else CollectorPollResult(
                        events=collector.collect(),
                        successful=True,
                        status="ok",
                    )
                )
                events = normalize_events(poll_result.events)
                cursor = collector.cursor if hasattr(collector, "cursor") else None
                if isinstance(cursor, dict):
                    inserted, by_type = self.storage.insert_events_and_update_collector_state(
                        events,
                        collector.collector_id,
                        poll_result.status,
                        cursor,
                        poll_result.error_class,
                        collection_session_id=self._session_id,
                        collector_version=collector.version,
                    )
                else:
                    inserted, by_type = self.storage._insert_events_with_metadata(
                        events,
                        collection_session_id=self._session_id,
                        collector_id=collector.collector_id,
                        collector_version=collector.version,
                    )
                self._counters[collector.collector_id] += inserted
                for event_type, count in by_type.items():
                    self._counters[event_type] += count
                if poll_result.warnings:
                    self._errors.extend(
                        f"{collector.collector_id}: warning:{warning}"
                        for warning in poll_result.warnings
                    )
                if poll_result.error_class:
                    self._errors.append(f"{collector.collector_id}: {poll_result.error_class}")
                self._status[collector.collector_id] = collector.health().__dict__
                self.storage.record_collector_observation(
                    session_id=self._session_id,
                    collector_id=collector.collector_id,
                    user_id=getattr(collector, "user_id", None),
                    host_id=getattr(collector, "host_id", None),
                    observed_at=observed_at,
                    status=poll_result.status,
                    successful_poll=poll_result.successful,
                    error_class=poll_result.error_class,
                    configured_interval_seconds=interval_seconds,
                    returned_events=len(poll_result.events),
                    saved_events=inserted,
                )
                any_success = any_success or poll_result.successful
            except Exception as exc:  # noqa: BLE001
                message = f"{collector.collector_id}: {type(exc).__name__}"
                self._errors.append(message)
                self.storage.upsert_collector_state(collector.collector_id, "error", {}, message)
                self.storage.record_collector_observation(
                    session_id=self._session_id,
                    collector_id=collector.collector_id,
                    user_id=getattr(collector, "user_id", None),
                    host_id=getattr(collector, "host_id", None),
                    observed_at=observed_at,
                    status="error",
                    successful_poll=False,
                    error_class=type(exc).__name__,
                    configured_interval_seconds=interval_seconds,
                    returned_events=0,
                    saved_events=0,
                )
        return any_success


_MANAGER: CollectorManager | None = None
_MANAGER_LOCK = threading.Lock()


def get_manager(settings: Settings) -> CollectorManager:
    global _MANAGER
    with _MANAGER_LOCK:
        if _MANAGER is None or _MANAGER.settings.database_path != settings.database_path:
            _MANAGER = CollectorManager(settings)
        return _MANAGER
