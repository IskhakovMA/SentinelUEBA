from __future__ import annotations

import platform
import xml.etree.ElementTree as ET
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
SYSTEM_ACCOUNTS = {"system", "local service", "network service"}


def parse_auth_fixture(payload: dict[str, Any]) -> dict[str, object] | None:
    return parse_auth_payload(_normalize_fixture_payload(payload))


def parse_auth_xml(xml_text: str) -> dict[str, object] | None:
    return parse_auth_payload(_normalize_xml_payload(xml_text))


def parse_auth_payload(payload: dict[str, object]) -> dict[str, object] | None:
    event_id = _int_value(payload.get("event_id"))
    if event_id not in AUTH_EVENT_MAP:
        return None
    logon_type = _int_or_none(payload.get("logon_type"))
    if logon_type is not None and logon_type not in INTERACTIVE_LOGON_TYPES:
        return None
    account = str(payload.get("target_user_name") or "").strip()
    if not account:
        return None
    if account.endswith("$") or account.lower() in SYSTEM_ACCOUNTS:
        return None
    action, result = AUTH_EVENT_MAP[event_id]
    parsed: dict[str, object] = {
        "action": action,
        "result": result,
        "method": "windows_security_log",
        "event_id": event_id,
        "record_id": _int_value(payload.get("record_id")),
    }
    if logon_type is not None:
        parsed["logon_type"] = logon_type
    for source_key, target_key in [
        ("target_domain_name", "target_domain_name"),
        ("failure_reason", "failure_reason"),
        ("status", "status"),
        ("sub_status", "sub_status"),
    ]:
        value = str(payload.get(source_key) or "").strip()
        if value:
            parsed[target_key] = value
    return parsed


class WindowsAuthCollector:
    collector_id = "windows.auth.security_event_log"
    version = "1.1"
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
            evt = _evt_module()
        except ImportError:
            return CollectorCapability(
                self.collector_id,
                self.version,
                CollectorStatus.UNAVAILABLE,
                self.required_privilege,
                "Optional Windows Security Event Log collector.",
                ["pywin32 is unavailable"],
            )
        handle: object | None = None
        try:
            handle = evt.EvtQuery(
                Path="Security",
                Flags=evt.EvtQueryChannelPath,
                Query=_event_query(0),
            )
        except Exception as exc:  # noqa: BLE001 - pywin32 raises dynamic permission errors.
            return CollectorCapability(
                self.collector_id,
                self.version,
                CollectorStatus.PERMISSION_REQUIRED,
                self.required_privilege,
                "Reads 4624/4625/4634/4647 from Windows Security Event Log.",
                [type(exc).__name__],
            )
        finally:
            if handle is not None:
                _close_evt_handle(evt, handle)
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

    def _latest_record_id(self) -> int:
        evt = _evt_module()
        query_handle: object | None = None
        event_handles: list[object] = []
        latest = self._last_record_id()
        try:
            query_handle = evt.EvtQuery(
                Path="Security",
                Flags=evt.EvtQueryChannelPath | evt.EvtQueryReverseDirection,
                Query=_event_query(0),
            )
            event_handles = list(evt.EvtNext(query_handle, 1))
            if event_handles:
                payload = _normalize_xml_payload(
                    str(evt.EvtRender(event_handles[0], evt.EvtRenderEventXml))
                )
                latest = _int_value(payload.get("record_id"))
        except Exception as exc:  # noqa: BLE001
            self._errors.append(type(exc).__name__)
        finally:
            for handle in event_handles:
                _close_evt_handle(evt, handle)
            if query_handle is not None:
                _close_evt_handle(evt, query_handle)
        return latest

    def _read_live_events(self) -> list[TelemetryEvent]:
        evt = _evt_module()
        query_handle: object | None = None
        output: list[TelemetryEvent] = []
        max_record_id = self._last_record_id()
        try:
            query_handle = evt.EvtQuery(
                Path="Security",
                Flags=evt.EvtQueryChannelPath,
                Query=_event_query(max_record_id),
            )
            while True:
                event_handles = list(evt.EvtNext(query_handle, 32))
                if not event_handles:
                    break
                try:
                    for event_handle in event_handles:
                        xml_text = str(evt.EvtRender(event_handle, evt.EvtRenderEventXml))
                        payload = _normalize_xml_payload(xml_text)
                        record_id = _int_value(payload.get("record_id"))
                        max_record_id = max(max_record_id, record_id)
                        parsed = parse_auth_payload(payload)
                        if parsed is None:
                            continue
                        output.append(self._event_from_parsed(parsed, payload))
                finally:
                    for event_handle in event_handles:
                        _close_evt_handle(evt, event_handle)
        finally:
            if query_handle is not None:
                _close_evt_handle(evt, query_handle)
        self.cursor["last_record_id"] = max_record_id
        return output

    def event_from_fixture(
        self,
        payload: dict[str, Any],
        timestamp: datetime,
    ) -> TelemetryEvent | None:
        normalized = _normalize_fixture_payload(payload)
        parsed = parse_auth_payload(normalized)
        if parsed is None:
            return None
        record_id = _int_value(parsed["record_id"])
        if record_id <= self._last_record_id():
            return None
        self.cursor["last_record_id"] = record_id
        normalized["time_created"] = timestamp.isoformat()
        return self._event_from_parsed(parsed, normalized)

    def _event_from_parsed(
        self,
        parsed: dict[str, object],
        normalized: dict[str, object],
    ) -> TelemetryEvent:
        record_id = _int_value(parsed["record_id"])
        return TelemetryEvent(
            event_id=deterministic_event_id([self.collector_id, str(record_id)]),
            timestamp=_parse_time(str(normalized.get("time_created") or "")),
            event_type=EventType.AUTHENTICATION,
            user_id=self.user_id,
            host_id=self.host_id,
            source=self.collector_id,
            payload=parsed,
            synthetic=False,
        )

    def _last_record_id(self) -> int:
        return _int_value(self.cursor.get("last_record_id", 0))


def _event_query(last_record_id: int) -> str:
    ids = " or ".join(f"EventID={event_id}" for event_id in AUTH_EVENT_MAP)
    return f"*[System[({ids}) and EventRecordID>{last_record_id}]]"


def _normalize_fixture_payload(payload: dict[str, Any]) -> dict[str, object]:
    return {
        "event_id": payload.get("EventID", payload.get("event_id")),
        "record_id": payload.get(
            "EventRecordID",
            payload.get("RecordID", payload.get("record_id")),
        ),
        "time_created": payload.get("TimeCreated", payload.get("time_created")),
        "target_user_name": payload.get("TargetUserName", payload.get("target_user_name")),
        "target_domain_name": payload.get("TargetDomainName", payload.get("target_domain_name")),
        "logon_type": payload.get("LogonType", payload.get("logon_type")),
        "failure_reason": payload.get("FailureReason", payload.get("failure_reason")),
        "status": payload.get("Status", payload.get("status")),
        "sub_status": payload.get("SubStatus", payload.get("sub_status")),
    }


def _normalize_xml_payload(xml_text: str) -> dict[str, object]:
    root = ET.fromstring(xml_text)
    namespace = {"e": "http://schemas.microsoft.com/win/2004/08/events/event"}

    def find_text(path: str) -> str:
        node = root.find(path, namespace)
        return node.text if node is not None and node.text is not None else ""

    def event_data(name: str) -> str:
        for node in root.findall(".//e:EventData/e:Data", namespace):
            if node.attrib.get("Name") == name:
                return node.text or ""
        return ""

    time_node = root.find(".//e:System/e:TimeCreated", namespace)
    return {
        "event_id": find_text(".//e:System/e:EventID"),
        "record_id": find_text(".//e:System/e:EventRecordID"),
        "time_created": time_node.attrib.get("SystemTime", "") if time_node is not None else "",
        "target_user_name": event_data("TargetUserName"),
        "target_domain_name": event_data("TargetDomainName"),
        "logon_type": event_data("LogonType"),
        "failure_reason": event_data("FailureReason"),
        "status": event_data("Status"),
        "sub_status": event_data("SubStatus"),
    }


def _parse_time(value: str) -> datetime:
    if not value:
        return datetime.now(UTC)
    normalized = value.replace("Z", "+00:00")
    try:
        parsed = datetime.fromisoformat(normalized)
    except ValueError:
        return datetime.now(UTC)
    return parsed.replace(tzinfo=UTC) if parsed.tzinfo is None else parsed.astimezone(UTC)


def _close_evt_handle(evt: Any, handle: object) -> None:
    close = evt.EvtClose
    close(handle)


def _evt_module() -> Any:
    import win32evtlog

    return win32evtlog


def _int_or_none(value: object) -> int | None:
    try:
        return int(str(value)) if value is not None and value != "" else None
    except (TypeError, ValueError):
        return None


def _int_value(value: object) -> int:
    parsed = _int_or_none(value)
    return parsed if parsed is not None else 0
