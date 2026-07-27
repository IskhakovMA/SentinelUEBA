from __future__ import annotations

import hashlib
import json
import math
from datetime import UTC
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator

from sentinelueba.domain.events import EventType, TelemetryEvent
from sentinelueba.normalization.normalizer import normalize_event

EVENT_SCHEMA_VERSION = "event-v1"
MAX_STRING_LENGTH = 512
MAX_PAYLOAD_BYTES = 8192


class ValidationSuccess(BaseModel):
    event: TelemetryEvent
    payload_hash: str
    event_schema_version: str = EVENT_SCHEMA_VERSION


class ValidationFailure(BaseModel):
    reason: str
    error_class: str
    safe_event: dict[str, Any]
    payload_hash: str
    event_schema_version: str = EVENT_SCHEMA_VERSION


class StrictPayload(BaseModel):
    model_config = ConfigDict(extra="forbid")

    @field_validator("*", mode="before")
    @classmethod
    def reject_nan_inf_and_large_strings(cls, value: Any) -> Any:
        if isinstance(value, float) and (math.isnan(value) or math.isinf(value)):
            raise ValueError("numeric payload values must be finite")
        if isinstance(value, str) and len(value) > MAX_STRING_LENGTH:
            raise ValueError("payload string is too long")
        return value


class ProcessPayload(StrictPayload):
    action: Literal["started", "stopped", "snapshot"] = "snapshot"
    process_name: str = Field(min_length=1, max_length=MAX_STRING_LENGTH)
    pid: int | None = Field(default=None, ge=0, le=4_294_967_295)
    executable_path: str | None = Field(default=None, max_length=MAX_STRING_LENGTH)
    parent_pid: int | None = Field(default=None, ge=0, le=4_294_967_295)
    parent_process: str | None = Field(default=None, max_length=MAX_STRING_LENGTH)
    command_family: str | None = Field(default=None, max_length=128)


class NetworkPayload(StrictPayload):
    action: Literal["opened", "closed", "snapshot"] = "snapshot"
    remote_address: str = Field(min_length=1, max_length=128)
    remote_port: int = Field(ge=0, le=65535)
    local_port: int | None = Field(default=None, ge=0, le=65535)
    protocol: Literal["tcp", "udp", "icmp", "other"] = "tcp"
    state: str | None = Field(default=None, max_length=64)
    pid: int | None = Field(default=None, ge=0, le=4_294_967_295)
    process_name: str | None = Field(default=None, max_length=MAX_STRING_LENGTH)
    connection_count: int | None = Field(default=None, ge=0, le=1_000_000)


class SystemMetricsPayload(StrictPayload):
    cpu_percent: float = Field(ge=0.0, le=100.0)
    ram_percent: float = Field(ge=0.0, le=100.0)
    disk_percent: float | None = Field(default=None, ge=0.0, le=100.0)
    network_bytes_sent_delta: int | None = Field(default=None, ge=0)
    network_bytes_recv_delta: int | None = Field(default=None, ge=0)
    boot_time: float | None = Field(default=None, ge=0.0)
    uptime_seconds: float | None = Field(default=None, ge=0.0)


class AuthenticationPayload(StrictPayload):
    action: Literal["login", "logout", "authentication"] = "authentication"
    result: Literal["success", "failure"]
    method: str | None = Field(default=None, max_length=128)
    failure_reason: str | None = Field(default=None, max_length=MAX_STRING_LENGTH)
    event_id: int | None = Field(default=None, ge=0)
    record_id: int | None = Field(default=None, ge=0)
    logon_type: int | None = Field(default=None, ge=0, le=99)


PAYLOAD_MODELS: dict[EventType, type[StrictPayload]] = {
    EventType.PROCESS: ProcessPayload,
    EventType.NETWORK: NetworkPayload,
    EventType.SYSTEM_METRICS: SystemMetricsPayload,
    EventType.AUTHENTICATION: AuthenticationPayload,
}


def validate_event(event: TelemetryEvent) -> ValidationSuccess | ValidationFailure:
    try:
        normalized = normalize_event(event)
        if normalized.timestamp.tzinfo is None:
            raise ValueError("timestamp must be timezone-aware")
        timestamp = normalized.timestamp.astimezone(UTC)
        if timestamp.year < 2000 or timestamp.year > 2100:
            raise ValueError("timestamp is outside supported range")
        serialized = _canonical_json(normalized.payload)
        if len(serialized.encode("utf-8")) > MAX_PAYLOAD_BYTES:
            raise ValueError("payload is too large")
        payload_model = PAYLOAD_MODELS[normalized.event_type]
        payload = payload_model.model_validate(normalized.payload).model_dump(exclude_none=True)
        clean = normalized.model_copy(
            update={
                "timestamp": timestamp,
                "payload": payload,
                "schema_version": EVENT_SCHEMA_VERSION,
            }
        )
        return ValidationSuccess(event=clean, payload_hash=payload_hash(payload))
    except (ValidationError, ValueError, KeyError, TypeError) as exc:
        return ValidationFailure(
            reason=str(exc),
            error_class=type(exc).__name__,
            safe_event=safe_quarantine_event(event),
            payload_hash=payload_hash(event.payload),
        )


def payload_hash(payload: dict[str, Any]) -> str:
    try:
        canonical = _canonical_json(payload)
    except (TypeError, ValueError):
        canonical = json.dumps(_json_safe(payload), sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def safe_quarantine_event(event: TelemetryEvent) -> dict[str, Any]:
    normalized = normalize_event(event)
    return {
        "event_id": normalized.event_id,
        "timestamp": normalized.timestamp.astimezone(UTC).isoformat(),
        "event_type": normalized.event_type.value,
        "user_id": normalized.user_id,
        "host_id": normalized.host_id,
        "source": normalized.source,
        "synthetic": normalized.synthetic,
        "payload": _json_safe(normalized.payload),
    }


def _canonical_json(payload: dict[str, Any]) -> str:
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), allow_nan=False)


def _json_safe(value: Any) -> Any:
    if isinstance(value, float) and (math.isnan(value) or math.isinf(value)):
        return str(value)
    if isinstance(value, dict):
        return {str(key): _json_safe(item) for key, item in value.items()}
    if isinstance(value, list):
        return [_json_safe(item) for item in value]
    return value
