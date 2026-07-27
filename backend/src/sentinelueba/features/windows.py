from __future__ import annotations

import hashlib
import json
from collections import defaultdict
from datetime import UTC, datetime, timedelta
from statistics import mean
from uuid import uuid5

from sentinelueba.domain.events import DEMO_NAMESPACE, EventType, TelemetryEvent, WindowFeatures

FEATURE_SCHEMA_VERSION = "feature-windows-v2"
FEATURE_NAMES = [
    "process_count",
    "new_process_count",
    "network_connection_count",
    "new_remote_count",
    "avg_cpu_percent",
    "max_cpu_percent",
    "avg_ram_percent",
    "max_ram_percent",
    "auth_success_count",
    "auth_failure_count",
    "hour_of_day",
    "activity_density",
]


def build_feature_windows(
    events: list[TelemetryEvent],
    window_minutes: int = 15,
) -> list[WindowFeatures]:
    if not events:
        return []
    grouped = group_events_by_profile_window(events, window_minutes)
    seen_processes: dict[tuple[str, str], set[str]] = defaultdict(set)
    seen_remotes: dict[tuple[str, str], set[str]] = defaultdict(set)
    windows: list[WindowFeatures] = []
    for (user_id, host_id, window_start), group in grouped.items():
        key = (user_id, host_id)
        values, process_names, remote_ids = feature_values_for_group(
            group,
            window_start,
            window_minutes,
            seen_processes[key],
            seen_remotes[key],
        )
        seen_processes[key].update(process_names)
        seen_remotes[key].update(remote_ids)
        windows.append(
            WindowFeatures(
                window_start=window_start,
                window_end=window_start + timedelta(minutes=window_minutes),
                user_id=user_id,
                host_id=host_id,
                features=values,
            )
        )

    return windows


def group_events_by_profile_window(
    events: list[TelemetryEvent],
    window_minutes: int = 15,
) -> dict[tuple[str, str, datetime], list[TelemetryEvent]]:
    grouped: dict[tuple[str, str, datetime], list[TelemetryEvent]] = defaultdict(list)
    for event in sorted(events, key=lambda item: (item.timestamp, item.event_id)):
        window_start = align_window_start(event.timestamp, window_minutes)
        grouped[(event.user_id, event.host_id, window_start)].append(event)
    return dict(sorted(grouped.items(), key=lambda item: item[0]))


def align_window_start(timestamp: datetime, window_minutes: int = 15) -> datetime:
    utc = timestamp.astimezone(UTC)
    total_minutes = utc.hour * 60 + utc.minute
    aligned_minutes = total_minutes - (total_minutes % window_minutes)
    return utc.replace(
        hour=aligned_minutes // 60,
        minute=aligned_minutes % 60,
        second=0,
        microsecond=0,
    )


def feature_values_for_group(
    group: list[TelemetryEvent],
    window_start: datetime,
    window_minutes: int,
    seen_processes: set[str],
    seen_remotes: set[str],
) -> tuple[dict[str, float], set[str], set[str]]:
    process_names = {
        str(event.payload.get("process_name", ""))
        for event in group
        if event.event_type == EventType.PROCESS
    }
    remote_ids = {
        f"{event.payload.get('remote_address')}:{event.payload.get('remote_port')}"
        for event in group
        if event.event_type == EventType.NETWORK
    }
    cpu_values = [
        float(event.payload.get("cpu_percent", 0.0))
        for event in group
        if event.event_type == EventType.SYSTEM_METRICS
    ]
    ram_values = [
        float(event.payload.get("ram_percent", 0.0))
        for event in group
        if event.event_type == EventType.SYSTEM_METRICS
    ]
    auth_success = sum(
        1
        for event in group
        if event.event_type == EventType.AUTHENTICATION and event.payload.get("result") == "success"
    )
    auth_failure = sum(
        1
        for event in group
        if event.event_type == EventType.AUTHENTICATION and event.payload.get("result") == "failure"
    )
    new_processes = process_names - seen_processes
    new_remotes = remote_ids - seen_remotes
    values = {
        "process_count": float(len(process_names)),
        "new_process_count": float(len(new_processes)),
        "network_connection_count": float(len(remote_ids)),
        "new_remote_count": float(len(new_remotes)),
        "avg_cpu_percent": float(mean(cpu_values)) if cpu_values else 0.0,
        "max_cpu_percent": float(max(cpu_values)) if cpu_values else 0.0,
        "avg_ram_percent": float(mean(ram_values)) if ram_values else 0.0,
        "max_ram_percent": float(max(ram_values)) if ram_values else 0.0,
        "auth_success_count": float(auth_success),
        "auth_failure_count": float(auth_failure),
        "hour_of_day": float(window_start.hour),
        "activity_density": float(len(group) / window_minutes),
    }
    return values, process_names, remote_ids


def deterministic_window_id(
    dataset_kind: str,
    user_id: str,
    host_id: str,
    window_start: datetime,
    window_end: datetime,
) -> str:
    return str(
        uuid5(
            DEMO_NAMESPACE,
            "|".join(
                [
                    dataset_kind,
                    user_id,
                    host_id,
                    window_start.isoformat(),
                    window_end.isoformat(),
                    FEATURE_SCHEMA_VERSION,
                ]
            ),
        )
    )


def source_event_hash(events: list[TelemetryEvent]) -> str:
    payload = [
        [event.event_id, event.timestamp.isoformat(), event.event_type.value]
        for event in sorted(events, key=lambda item: item.event_id)
    ]
    return hashlib.sha256(json.dumps(payload, separators=(",", ":")).encode("utf-8")).hexdigest()


def windows_to_matrix(windows: list[WindowFeatures]) -> list[list[float]]:
    return [[window.features[name] for name in FEATURE_NAMES] for window in windows]
