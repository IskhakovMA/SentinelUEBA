from __future__ import annotations

from typing import Any

from sentinelueba.domain.events import EventType, TelemetryEvent

ALLOWED_PAYLOAD_KEYS: dict[EventType, set[str]] = {
    EventType.PROCESS: {"process_name", "pid", "parent_process", "command_family"},
    EventType.NETWORK: {"remote_address", "remote_port", "protocol", "connection_count"},
    EventType.SYSTEM_METRICS: {"cpu_percent", "ram_percent"},
    EventType.AUTHENTICATION: {"result", "method", "failure_reason"},
}


def normalize_event(event: TelemetryEvent | dict[str, Any]) -> TelemetryEvent:
    parsed = event if isinstance(event, TelemetryEvent) else TelemetryEvent.model_validate(event)
    allowed = ALLOWED_PAYLOAD_KEYS[parsed.event_type]
    safe_payload = {key: value for key, value in parsed.payload.items() if key in allowed}
    return parsed.model_copy(update={"payload": safe_payload})


def normalize_events(events: list[TelemetryEvent]) -> list[TelemetryEvent]:
    return [normalize_event(event) for event in events]

