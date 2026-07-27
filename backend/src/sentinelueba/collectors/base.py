from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import StrEnum
from typing import Protocol

from sentinelueba.domain.events import TelemetryEvent


class CollectorStatus(StrEnum):
    AVAILABLE = "available"
    UNAVAILABLE = "unavailable"
    PERMISSION_REQUIRED = "permission_required"
    RUNNING = "running"
    STOPPED = "stopped"
    ERROR = "error"


class PrivilegeLevel(StrEnum):
    USER = "user"
    ADMIN_OPTIONAL = "admin_optional"
    ADMIN_REQUIRED = "admin_required"


@dataclass(frozen=True)
class CollectorCapability:
    collector_id: str
    version: str
    status: CollectorStatus
    required_privilege: PrivilegeLevel
    description: str
    errors: list[str] = field(default_factory=list)


@dataclass
class CollectorHealth:
    collector_id: str
    status: CollectorStatus
    last_checked_at: datetime = field(default_factory=lambda: datetime.now(UTC))
    errors: list[str] = field(default_factory=list)
    events_collected: int = 0


class TelemetryCollector(Protocol):
    collector_id: str
    version: str
    required_privilege: PrivilegeLevel

    def check_availability(self) -> CollectorCapability:
        """Return capability without raising on unsupported platforms or missing rights."""

    def start(self) -> None:
        """Initialize collector state."""

    def stop(self) -> None:
        """Stop collector state."""

    def health(self) -> CollectorHealth:
        """Return latest health and errors."""

    def collect(self) -> list[TelemetryEvent]:
        """Collect a polling batch and convert it to normalized telemetry events."""

