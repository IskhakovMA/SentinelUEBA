from __future__ import annotations

import platform
from datetime import UTC, datetime

import psutil

from sentinelueba.collectors.base import (
    CollectorCapability,
    CollectorHealth,
    CollectorStatus,
    PrivilegeLevel,
)
from sentinelueba.domain.events import EventType, TelemetryEvent, deterministic_event_id


class SystemMetricsCollector:
    collector_id = "windows.system_metrics.psutil"
    version = "1.0"
    required_privilege = PrivilegeLevel.USER

    def __init__(self, user_id: str, host_id: str) -> None:
        self.user_id = user_id
        self.host_id = host_id
        self._previous_net: tuple[int, int] | None = None
        self._errors: list[str] = []
        self._events = 0

    def check_availability(self) -> CollectorCapability:
        if platform.system() != "Windows":
            return CollectorCapability(
                self.collector_id,
                self.version,
                CollectorStatus.UNAVAILABLE,
                self.required_privilege,
                "Windows system metrics via psutil.",
                ["collector is Windows-only"],
            )
        return CollectorCapability(
            self.collector_id,
            self.version,
            CollectorStatus.AVAILABLE,
            self.required_privilege,
            "Collects CPU, RAM, disk, network byte deltas, and uptime.",
        )

    def start(self) -> None:
        counters = psutil.net_io_counters()
        self._previous_net = (int(counters.bytes_sent), int(counters.bytes_recv))
        self._errors.clear()

    def stop(self) -> None:
        self._previous_net = None

    def health(self) -> CollectorHealth:
        status = CollectorStatus.ERROR if self._errors else CollectorStatus.RUNNING
        return CollectorHealth(
            self.collector_id,
            status,
            errors=self._errors[-5:],
            events_collected=self._events,
        )

    def collect(self) -> list[TelemetryEvent]:
        timestamp = datetime.now(UTC)
        try:
            cpu = float(psutil.cpu_percent(interval=None))
            ram = float(psutil.virtual_memory().percent)
            disk = float(psutil.disk_usage("/").percent)
            boot_time = float(psutil.boot_time())
            counters = psutil.net_io_counters()
            current = (int(counters.bytes_sent), int(counters.bytes_recv))
            previous = self._previous_net or current
            self._previous_net = current
            payload = {
                "cpu_percent": cpu,
                "ram_percent": ram,
                "disk_percent": disk,
                "network_bytes_sent_delta": max(0, current[0] - previous[0]),
                "network_bytes_recv_delta": max(0, current[1] - previous[1]),
                "boot_time": boot_time,
                "uptime_seconds": max(0.0, timestamp.timestamp() - boot_time),
            }
        except OSError as exc:
            self._errors.append(type(exc).__name__)
            return []
        self._events += 1
        return [
            TelemetryEvent(
                event_id=deterministic_event_id(
                    [self.collector_id, timestamp.isoformat(), self.user_id, self.host_id]
                ),
                timestamp=timestamp,
                event_type=EventType.SYSTEM_METRICS,
                user_id=self.user_id,
                host_id=self.host_id,
                source=self.collector_id,
                payload=payload,
                synthetic=False,
            )
        ]
