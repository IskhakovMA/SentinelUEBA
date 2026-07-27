from __future__ import annotations

from typing import Any

from sentinelueba.domain.events import EventType, TelemetryEvent

ALLOWED_PAYLOAD_KEYS: dict[EventType, set[str]] = {
    EventType.PROCESS: {
        "action",
        "process_name",
        "pid",
        "executable_path",
        "parent_pid",
        "parent_process",
        "command_family",
    },
    EventType.NETWORK: {
        "action",
        "remote_address",
        "remote_port",
        "local_port",
        "protocol",
        "state",
        "pid",
        "process_name",
        "connection_count",
    },
    EventType.SYSTEM_METRICS: {
        "cpu_percent",
        "ram_percent",
        "disk_percent",
        "network_bytes_sent_delta",
        "network_bytes_recv_delta",
        "boot_time",
        "uptime_seconds",
    },
    EventType.AUTHENTICATION: {
        "action",
        "result",
        "method",
        "failure_reason",
        "event_id",
        "record_id",
        "logon_type",
        "target_domain_name",
        "status",
        "sub_status",
    },
}


def normalize_event(event: TelemetryEvent | dict[str, Any]) -> TelemetryEvent:
    parsed = event if isinstance(event, TelemetryEvent) else TelemetryEvent.model_validate(event)
    allowed = ALLOWED_PAYLOAD_KEYS[parsed.event_type]
    safe_payload = {key: value for key, value in parsed.payload.items() if key in allowed}
    return parsed.model_copy(update={"payload": safe_payload})


def normalize_events(events: list[TelemetryEvent]) -> list[TelemetryEvent]:
    return [normalize_event(event) for event in events]
