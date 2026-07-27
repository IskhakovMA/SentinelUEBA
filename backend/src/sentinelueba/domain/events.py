from __future__ import annotations

from datetime import UTC, datetime
from enum import StrEnum
from typing import Any, Literal
from uuid import UUID, uuid5

from pydantic import BaseModel, ConfigDict, field_validator

SCHEMA_VERSION = "0.1"
DEMO_NAMESPACE = UUID("9f2db585-dffa-4a30-9828-a1cc21f75d10")


class EventType(StrEnum):
    PROCESS = "process"
    NETWORK = "network"
    SYSTEM_METRICS = "system_metrics"
    AUTHENTICATION = "authentication"


class TelemetryEvent(BaseModel):
    model_config = ConfigDict(frozen=True)

    event_id: str
    timestamp: datetime
    event_type: EventType
    user_id: str
    host_id: str
    source: str
    payload: dict[str, Any]
    synthetic: bool = True
    schema_version: str = SCHEMA_VERSION

    @field_validator("timestamp")
    @classmethod
    def require_utc(cls, value: datetime) -> datetime:
        if value.tzinfo is None:
            return value.replace(tzinfo=UTC)
        return value.astimezone(UTC)

    @field_validator("user_id", "host_id", "source")
    @classmethod
    def require_safe_identifier(cls, value: str) -> str:
        clean = value.strip()
        if not clean:
            raise ValueError("identifier must not be empty")
        if len(clean) > 128:
            raise ValueError("identifier is too long")
        return clean


class AnomalyRisk(StrEnum):
    NORMAL = "normal"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class AnomalyRecord(BaseModel):
    timestamp: datetime
    user_id: str
    host_id: str
    anomaly_score: float
    threshold: float
    risk_level: AnomalyRisk
    top_features: list[str]
    explanation: str
    model_version: str
    window_start: datetime
    window_end: datetime


class WindowFeatures(BaseModel):
    window_start: datetime
    window_end: datetime
    user_id: str
    host_id: str
    features: dict[str, float]


def deterministic_event_id(parts: list[str]) -> str:
    return str(uuid5(DEMO_NAMESPACE, "|".join(parts)))


RiskName = Literal["normal", "low", "medium", "high", "critical"]

