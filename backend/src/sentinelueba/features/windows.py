from __future__ import annotations

from collections import defaultdict
from datetime import timedelta
from statistics import mean

from sentinelueba.domain.events import EventType, TelemetryEvent, WindowFeatures

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
    ordered = sorted(events, key=lambda event: event.timestamp)
    first = ordered[0].timestamp.replace(minute=0, second=0, microsecond=0)
    last = ordered[-1].timestamp
    delta = timedelta(minutes=window_minutes)
    seen_processes: dict[tuple[str, str], set[str]] = defaultdict(set)
    seen_remotes: dict[tuple[str, str], set[str]] = defaultdict(set)
    windows: list[WindowFeatures] = []
    current = first

    while current <= last:
        end = current + delta
        bucket = [event for event in ordered if current <= event.timestamp < end]
        grouped: dict[tuple[str, str], list[TelemetryEvent]] = defaultdict(list)
        for event in bucket:
            grouped[(event.user_id, event.host_id)].append(event)

        for (user_id, host_id), group in grouped.items():
            key = (user_id, host_id)
            process_names = [
                str(event.payload.get("process_name", ""))
                for event in group
                if event.event_type == EventType.PROCESS
            ]
            remote_ids = [
                f"{event.payload.get('remote_address')}:{event.payload.get('remote_port')}"
                for event in group
                if event.event_type == EventType.NETWORK
            ]
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
                if event.event_type == EventType.AUTHENTICATION
                and event.payload.get("result") == "success"
            )
            auth_failure = sum(
                1
                for event in group
                if event.event_type == EventType.AUTHENTICATION
                and event.payload.get("result") == "failure"
            )
            new_processes = {name for name in process_names if name not in seen_processes[key]}
            new_remotes = {remote for remote in remote_ids if remote not in seen_remotes[key]}
            seen_processes[key].update(process_names)
            seen_remotes[key].update(remote_ids)

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
                "hour_of_day": float(current.hour),
                "activity_density": float(len(group) / window_minutes),
            }
            windows.append(
                WindowFeatures(
                    window_start=current,
                    window_end=end,
                    user_id=user_id,
                    host_id=host_id,
                    features=values,
                )
            )
        current = end

    return windows


def windows_to_matrix(windows: list[WindowFeatures]) -> list[list[float]]:
    return [[window.features[name] for name in FEATURE_NAMES] for window in windows]

