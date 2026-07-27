from __future__ import annotations

import platform
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

import psutil

from sentinelueba.collectors.base import (
    CollectorCapability,
    CollectorHealth,
    CollectorStatus,
    PrivilegeLevel,
)
from sentinelueba.domain.events import EventType, TelemetryEvent, deterministic_event_id


@dataclass(frozen=True)
class ProcessSnapshot:
    pid: int
    create_time: float
    name: str
    executable_path: str | None
    parent_pid: int | None
    parent_name: str | None

    @property
    def key(self) -> tuple[int, float]:
        return (self.pid, self.create_time)


def diff_process_snapshots(
    previous: dict[int, ProcessSnapshot],
    current: dict[int, ProcessSnapshot],
) -> list[tuple[str, ProcessSnapshot]]:
    events: list[tuple[str, ProcessSnapshot]] = []
    for pid, snapshot in current.items():
        if pid not in previous:
            events.append(("started", snapshot))
        elif previous[pid].create_time != snapshot.create_time:
            events.append(("stopped", previous[pid]))
            events.append(("started", snapshot))
    for pid, snapshot in previous.items():
        if pid not in current:
            events.append(("stopped", snapshot))
    return events


class ProcessCollector:
    collector_id = "windows.process.psutil"
    version = "1.0"
    required_privilege = PrivilegeLevel.USER

    def __init__(self, user_id: str, host_id: str) -> None:
        self.user_id = user_id
        self.host_id = host_id
        self._previous: dict[int, ProcessSnapshot] = {}
        self._errors: list[str] = []
        self._events = 0

    def check_availability(self) -> CollectorCapability:
        if platform.system() != "Windows":
            return CollectorCapability(
                self.collector_id,
                self.version,
                CollectorStatus.UNAVAILABLE,
                self.required_privilege,
                "Windows process polling via psutil.",
                ["collector is Windows-only"],
            )
        return CollectorCapability(
            self.collector_id,
            self.version,
            CollectorStatus.AVAILABLE,
            self.required_privilege,
            "Polls process snapshots and reports started/stopped processes.",
        )

    def start(self) -> None:
        self._previous = self.snapshot()
        self._errors.clear()

    def stop(self) -> None:
        self._previous = {}

    def health(self) -> CollectorHealth:
        status = CollectorStatus.ERROR if self._errors else CollectorStatus.RUNNING
        return CollectorHealth(
            self.collector_id,
            status,
            errors=self._errors[-5:],
            events_collected=self._events,
        )

    def collect(self) -> list[TelemetryEvent]:
        now = datetime.now(UTC)
        current = self.snapshot()
        changes = diff_process_snapshots(self._previous, current)
        self._previous = current
        events = [self._event(now, action, snapshot) for action, snapshot in changes]
        self._events += len(events)
        return events

    def snapshot(self) -> dict[int, ProcessSnapshot]:
        snapshots: dict[int, ProcessSnapshot] = {}
        for proc in psutil.process_iter(["pid", "name", "exe", "ppid", "create_time"]):
            try:
                info: dict[str, Any] = proc.info
                parent_name = None
                parent_pid = info.get("ppid")
                if isinstance(parent_pid, int) and parent_pid > 0:
                    try:
                        parent_name = psutil.Process(parent_pid).name()
                    except (psutil.AccessDenied, psutil.NoSuchProcess, psutil.ZombieProcess):
                        parent_name = None
                pid = int(info["pid"])
                snapshots[pid] = ProcessSnapshot(
                    pid=pid,
                    create_time=float(info.get("create_time") or 0.0),
                    name=str(info.get("name") or "unknown"),
                    executable_path=info.get("exe") if isinstance(info.get("exe"), str) else None,
                    parent_pid=parent_pid if isinstance(parent_pid, int) else None,
                    parent_name=parent_name,
                )
            except (psutil.AccessDenied, psutil.NoSuchProcess, psutil.ZombieProcess) as exc:
                self._errors.append(type(exc).__name__)
        return snapshots

    def _event(self, timestamp: datetime, action: str, snapshot: ProcessSnapshot) -> TelemetryEvent:
        payload = {
            "action": action,
            "pid": snapshot.pid,
            "process_name": snapshot.name,
            "executable_path": snapshot.executable_path,
            "parent_pid": snapshot.parent_pid,
            "parent_process": snapshot.parent_name,
        }
        return TelemetryEvent(
            event_id=deterministic_event_id(
                [
                    self.collector_id,
                    timestamp.isoformat(),
                    action,
                    str(snapshot.pid),
                    str(snapshot.create_time),
                    snapshot.name,
                ]
            ),
            timestamp=timestamp,
            event_type=EventType.PROCESS,
            user_id=self.user_id,
            host_id=self.host_id,
            source=self.collector_id,
            payload={key: value for key, value in payload.items() if value is not None},
            synthetic=False,
        )
