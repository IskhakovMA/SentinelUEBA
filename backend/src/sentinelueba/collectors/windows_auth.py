from __future__ import annotations

import platform
from datetime import UTC, datetime
from typing import Any

from sentinelueba.collectors.base import (
    CollectorCapability,
    CollectorHealth,
    CollectorStatus,
    PrivilegeLevel,
)
from sentinelueba.domain.events import EventType, TelemetryEvent, deterministic_event_id

AUTH_EVENT_MAP = {
    4624: ("login", "success"),
    4625: ("login", "failure"),
    4634: ("logout", "success"),
    4647: ("logout", "success"),
}
INTERACTIVE_LOGON_TYPES = {2, 7, 10, 11}


def parse_auth_fixture(payload: dict[str, Any]) -> dict[str, object] | None:
    event_id = int(payload.get("EventID", 0))
    if event_id not in AUTH_EVENT_MAP:
        return None
    logon_type = _int_or_none(payload.get("LogonType"))
    if logon_type is not None and logon_type not in INTERACTIVE_LOGON_TYPES:
        return None
    account = str(payload.get("TargetUserName") or "")
    if account.endswith("$") or account.lower() in {"system", "local service", "network service"}:
        return None
    action, result = AUTH_EVENT_MAP[event_id]
    return {
        "action": action,
        "result": result,
        "method": "windows_security_log",
        "event_id": event_id,
        "record_id": int(payload.get("RecordID", 0)),
        "logon_type": logon_type or 0,
        "failure_reason": str(payload.get("FailureReason") or ""),
    }


class WindowsAuthCollector:
    collector_id = "windows.auth.security_event_log"
    version = "1.0"
    required_privilege = PrivilegeLevel.ADMIN_OPTIONAL

    def __init__(self, user_id: str, host_id: str, cursor: dict[str, object] | None = None) -> None:
        self.user_id = user_id
        self.host_id = host_id
        self.cursor = cursor or {}
        self._errors: list[str] = []
        self._events = 0

    def check_availability(self) -> CollectorCapability:
        if platform.system() != "Windows":
            return CollectorCapability(
                self.collector_id,
                self.version,
                CollectorStatus.UNAVAILABLE,
                self.required_privilege,
                "Optional Windows Security Event Log collector.",
                ["collector is Windows-only"],
            )
        try:
            import win32evtlog  # noqa: F401
        except ImportError:
            return CollectorCapability(
                self.collector_id,
                self.version,
                CollectorStatus.UNAVAILABLE,
                self.required_privilege,
                "Optional Windows Security Event Log collector.",
                ["pywin32 is unavailable"],
            )
        try:
            self._open_security_log()
        except Exception as exc:  # noqa: BLE001 - Windows APIs raise pywintypes.error dynamically.
            return CollectorCapability(
                self.collector_id,
                self.version,
                CollectorStatus.PERMISSION_REQUIRED,
                self.required_privilege,
                "Reads 4624/4625/4634/4647 from Windows Security Event Log.",
                [type(exc).__name__],
            )
        return CollectorCapability(
            self.collector_id,
            self.version,
            CollectorStatus.AVAILABLE,
            self.required_privilege,
            "Reads interactive authentication events from current Security Log position.",
        )

    def start(self) -> None:
        self._errors.clear()
        if "last_record_id" not in self.cursor:
            self.cursor["last_record_id"] = self._latest_record_id()

    def stop(self) -> None:
        pass

    def health(self) -> CollectorHealth:
        status = CollectorStatus.ERROR if self._errors else CollectorStatus.RUNNING
        return CollectorHealth(
            self.collector_id,
            status,
            errors=self._errors[-5:],
            events_collected=self._events,
        )

    def collect(self) -> list[TelemetryEvent]:
        capability = self.check_availability()
        if capability.status != CollectorStatus.AVAILABLE:
            self._errors.extend(capability.errors)
            return []
        try:
            events = self._read_live_events()
            self._events += len(events)
            return events
        except Exception as exc:  # noqa: BLE001
            self._errors.append(type(exc).__name__)
            return []

    def _open_security_log(self) -> object:
        import win32evtlog

        return win32evtlog.OpenEventLog(None, "Security")

    def _latest_record_id(self) -> int:
        try:
            import win32evtlog

            handle = self._open_security_log()
            oldest = win32evtlog.GetOldestEventLogRecord(handle)
            count = win32evtlog.GetNumberOfEventLogRecords(handle)
            return int(oldest + count)
        except Exception as exc:  # noqa: BLE001
            self._errors.append(type(exc).__name__)
            return self._last_record_id()

    def _read_live_events(self) -> list[TelemetryEvent]:
        import win32evtlog

        handle = self._open_security_log()
        flags = win32evtlog.EVENTLOG_FORWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ
        last_record_id = self._last_record_id()
        output: list[TelemetryEvent] = []
        while True:
            records = win32evtlog.ReadEventLog(handle, flags, 0)
            if not records:
                break
            for record in records:
                record_id = int(record.RecordNumber)
                if record_id <= last_record_id:
                    continue
                event_id = int(record.EventID) & 0xFFFF
                last_record_id = max(last_record_id, record_id)
                if event_id not in AUTH_EVENT_MAP:
                    continue
                action, result = AUTH_EVENT_MAP[event_id]
                timestamp = getattr(record, "TimeGenerated", datetime.now(UTC))
                if not isinstance(timestamp, datetime):
                    timestamp = datetime.now(UTC)
                output.append(
                    TelemetryEvent(
                        event_id=deterministic_event_id([self.collector_id, str(record_id)]),
                        timestamp=timestamp.replace(tzinfo=UTC)
                        if timestamp.tzinfo is None
                        else timestamp.astimezone(UTC),
                        event_type=EventType.AUTHENTICATION,
                        user_id=self.user_id,
                        host_id=self.host_id,
                        source=self.collector_id,
                        payload={
                            "action": action,
                            "result": result,
                            "method": "windows_security_log",
                            "event_id": event_id,
                            "record_id": record_id,
                            "logon_type": 0,
                        },
                        synthetic=False,
                    )
                )
        self.cursor["last_record_id"] = last_record_id
        return output

    def event_from_fixture(
        self,
        payload: dict[str, Any],
        timestamp: datetime,
    ) -> TelemetryEvent | None:
        parsed = parse_auth_fixture(payload)
        if parsed is None:
            return None
        record_id = _int_value(parsed["record_id"])
        if record_id <= self._last_record_id():
            return None
        self.cursor["last_record_id"] = record_id
        return TelemetryEvent(
            event_id=deterministic_event_id([self.collector_id, str(record_id)]),
            timestamp=timestamp.astimezone(UTC),
            event_type=EventType.AUTHENTICATION,
            user_id=self.user_id,
            host_id=self.host_id,
            source=self.collector_id,
            payload=parsed,
            synthetic=False,
        )

    def _last_record_id(self) -> int:
        return _int_value(self.cursor.get("last_record_id", 0))


def _int_or_none(value: object) -> int | None:
    try:
        return int(str(value)) if value is not None and value != "" else None
    except (TypeError, ValueError):
        return None


def _int_value(value: object) -> int:
    parsed = _int_or_none(value)
    return parsed if parsed is not None else 0
