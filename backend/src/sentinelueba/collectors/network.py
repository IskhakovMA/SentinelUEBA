from __future__ import annotations

import platform
from dataclasses import dataclass
from datetime import UTC, datetime

import psutil

from sentinelueba.collectors.base import (
    CollectorCapability,
    CollectorHealth,
    CollectorStatus,
    PrivilegeLevel,
)
from sentinelueba.domain.events import EventType, TelemetryEvent, deterministic_event_id


@dataclass(frozen=True)
class NetworkSnapshot:
    protocol: str
    state: str
    remote_address: str | None
    remote_port: int | None
    local_port: int | None
    pid: int | None
    process_name: str | None

    @property
    def key(self) -> tuple[object, ...]:
        return (
            self.protocol,
            self.remote_address,
            self.remote_port,
            self.local_port,
            self.pid,
        )


def diff_network_snapshots(
    previous: dict[tuple[object, ...], NetworkSnapshot],
    current: dict[tuple[object, ...], NetworkSnapshot],
) -> list[tuple[str, NetworkSnapshot]]:
    changes: list[tuple[str, NetworkSnapshot]] = []
    for key, snapshot in current.items():
        if key not in previous:
            changes.append(("opened", snapshot))
    for key, snapshot in previous.items():
        if key not in current:
            changes.append(("closed", snapshot))
    return changes


class NetworkCollector:
    collector_id = "windows.network.psutil"
    version = "1.0"
    required_privilege = PrivilegeLevel.USER

    def __init__(self, user_id: str, host_id: str) -> None:
        self.user_id = user_id
        self.host_id = host_id
        self._previous: dict[tuple[object, ...], NetworkSnapshot] = {}
        self._errors: list[str] = []
        self._events = 0

    def check_availability(self) -> CollectorCapability:
        if platform.system() != "Windows":
            return CollectorCapability(
                self.collector_id,
                self.version,
                CollectorStatus.UNAVAILABLE,
                self.required_privilege,
                "Windows TCP/UDP connection polling via psutil.",
                ["collector is Windows-only"],
            )
        return CollectorCapability(
            self.collector_id,
            self.version,
            CollectorStatus.AVAILABLE,
            self.required_privilege,
            "Polls TCP/UDP connection metadata without packet capture.",
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
        changes = diff_network_snapshots(self._previous, current)
        self._previous = current
        events = [self._event(now, action, snapshot) for action, snapshot in changes]
        self._events += len(events)
        return events

    def snapshot(self) -> dict[tuple[object, ...], NetworkSnapshot]:
        snapshots: dict[tuple[object, ...], NetworkSnapshot] = {}
        try:
            connections = psutil.net_connections(kind="inet")
        except (psutil.AccessDenied, OSError) as exc:
            self._errors.append(type(exc).__name__)
            return snapshots
        for conn in connections:
            try:
                protocol = "tcp" if conn.type.name == "SOCK_STREAM" else "udp"
                remote_address = conn.raddr.ip if conn.raddr else None
                remote_port = int(conn.raddr.port) if conn.raddr else None
                local_port = int(conn.laddr.port) if conn.laddr else None
                process_name = None
                if conn.pid:
                    try:
                        process_name = psutil.Process(conn.pid).name()
                    except (psutil.AccessDenied, psutil.NoSuchProcess, psutil.ZombieProcess):
                        process_name = None
                snapshot = NetworkSnapshot(
                    protocol=protocol,
                    state=str(conn.status or "NONE"),
                    remote_address=remote_address,
                    remote_port=remote_port,
                    local_port=local_port,
                    pid=conn.pid,
                    process_name=process_name,
                )
                snapshots[snapshot.key] = snapshot
            except (psutil.AccessDenied, psutil.NoSuchProcess, OSError) as exc:
                self._errors.append(type(exc).__name__)
        return snapshots

    def _event(self, timestamp: datetime, action: str, snapshot: NetworkSnapshot) -> TelemetryEvent:
        payload = {
            "action": action,
            "protocol": snapshot.protocol,
            "state": snapshot.state,
            "remote_address": snapshot.remote_address,
            "remote_port": snapshot.remote_port,
            "local_port": snapshot.local_port,
            "pid": snapshot.pid,
            "process_name": snapshot.process_name,
        }
        return TelemetryEvent(
            event_id=deterministic_event_id(
                [self.collector_id, timestamp.isoformat(), action, repr(snapshot.key)]
            ),
            timestamp=timestamp,
            event_type=EventType.NETWORK,
            user_id=self.user_id,
            host_id=self.host_id,
            source=self.collector_id,
            payload={key: value for key, value in payload.items() if value is not None},
            synthetic=False,
        )
