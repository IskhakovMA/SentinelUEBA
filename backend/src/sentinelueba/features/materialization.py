from __future__ import annotations

from collections import Counter, defaultdict
from datetime import UTC, datetime, timedelta
from typing import Any

from sentinelueba.domain.events import EventType, TelemetryEvent
from sentinelueba.features.windows import (
    FEATURE_SCHEMA_VERSION,
    align_window_start,
    deterministic_window_id,
    feature_values_for_group,
    group_events_by_profile_window,
    source_event_hash,
)
from sentinelueba.storage.sqlite import SQLiteStorage

DEFAULT_WINDOW_MINUTES = 15
DEFAULT_LATE_EVENT_MINUTES = 60


class FeatureMaterializer:
    def __init__(
        self,
        storage: SQLiteStorage,
        *,
        window_minutes: int = DEFAULT_WINDOW_MINUTES,
        late_event_minutes: int = DEFAULT_LATE_EVENT_MINUTES,
    ) -> None:
        self.storage = storage
        self.window_minutes = window_minutes
        self.late_event_minutes = late_event_minutes

    def materialize(self, dataset_kind: str, *, rebuild: bool = False) -> dict[str, Any]:
        synthetic = dataset_kind == "synthetic"
        state = self.storage.get_materialization_state(dataset_kind)
        event_rows = self.storage.list_event_rows(synthetic=synthetic)
        events = [row["event"] for row in event_rows]
        if not events:
            if rebuild:
                self.storage.delete_feature_windows(dataset_kind)
            self.storage.upsert_materialization_state(
                dataset_kind,
                watermark=None,
                late_event_interval_minutes=self.late_event_minutes,
                window_size_minutes=self.window_minutes,
                baseline_state={},
                rebuilt=rebuild,
            )
            return {
                "dataset_kind": dataset_kind,
                "processed_events": 0,
                "upserted_windows": 0,
                "deleted_windows": 0,
                "watermark": None,
                "rebuild": rebuild,
            }

        watermark = max(event.timestamp for event in events)
        affected_start: datetime | None = None
        if state and state.get("watermark") and not rebuild:
            previous = datetime.fromisoformat(str(state["watermark"]))
            late_boundary = previous - timedelta(minutes=self.late_event_minutes)
            changed = [event for event in events if event.timestamp >= late_boundary]
            if changed:
                affected_start = align_window_start(
                    min(event.timestamp for event in changed),
                    self.window_minutes,
                )
        if rebuild or affected_start is None:
            affected_start = align_window_start(
                min(event.timestamp for event in events),
                self.window_minutes,
            )

        deleted = self.storage.delete_feature_windows(
            dataset_kind,
            from_start=None if rebuild else affected_start,
        )
        windows = self._build_windows(
            events,
            dataset_kind=dataset_kind,
            from_start=affected_start,
            sessions=self.storage.list_sessions() if dataset_kind == "real" else [],
        )
        upserted = self.storage.upsert_feature_windows(windows)
        self.storage.upsert_materialization_state(
            dataset_kind,
            watermark=watermark,
            late_event_interval_minutes=self.late_event_minutes,
            window_size_minutes=self.window_minutes,
            baseline_state=self._baseline_state(events),
            rebuilt=rebuild,
        )
        return {
            "dataset_kind": dataset_kind,
            "processed_events": len(events),
            "upserted_windows": upserted,
            "deleted_windows": deleted,
            "watermark": watermark.isoformat(),
            "rebuild": rebuild,
            "late_event_interval_minutes": self.late_event_minutes,
            "window_size_minutes": self.window_minutes,
        }

    def status(self) -> dict[str, Any]:
        return {
            "synthetic": self.storage.get_materialization_state("synthetic"),
            "real": self.storage.get_materialization_state("real"),
            "windows": self.storage.feature_window_summary(),
        }

    def _build_windows(
        self,
        events: list[TelemetryEvent],
        *,
        dataset_kind: str,
        from_start: datetime,
        sessions: list[dict[str, Any]],
    ) -> list[dict[str, Any]]:
        grouped = group_events_by_profile_window(events, self.window_minutes)
        seen_processes: dict[tuple[str, str], set[str]] = defaultdict(set)
        seen_remotes: dict[tuple[str, str], set[str]] = defaultdict(set)
        windows: list[dict[str, Any]] = []
        for (user_id, host_id, window_start), group in grouped.items():
            key = (user_id, host_id)
            window_end = window_start + timedelta(minutes=self.window_minutes)
            values, process_names, remote_ids = feature_values_for_group(
                group,
                window_start,
                self.window_minutes,
                seen_processes[key],
                seen_remotes[key],
            )
            seen_processes[key].update(process_names)
            seen_remotes[key].update(remote_ids)
            if window_start < from_start:
                continue
            quality = quality_for_window(
                group,
                dataset_kind=dataset_kind,
                window_start=window_start,
                window_end=window_end,
                sessions=sessions,
            )
            counts = Counter(event.event_type.value for event in group)
            collectors = Counter(event.source for event in group)
            windows.append(
                {
                    "window_id": deterministic_window_id(
                        dataset_kind,
                        user_id,
                        host_id,
                        window_start,
                        window_end,
                    ),
                    "dataset_kind": dataset_kind,
                    "user_id": user_id,
                    "host_id": host_id,
                    "window_start": window_start.isoformat(),
                    "window_end": window_end.isoformat(),
                    "feature_schema_version": FEATURE_SCHEMA_VERSION,
                    "window_size_minutes": self.window_minutes,
                    "features": values,
                    "event_count": len(group),
                    "event_counts": dict(counts),
                    "collector_coverage": {
                        "event_sources": dict(collectors),
                        "heartbeat_coverage": quality["heartbeat_coverage"],
                    },
                    "quality_status": quality["status"],
                    "quality_reasons": quality["reasons"],
                    "gap_duration_seconds": quality["gap_duration_seconds"],
                    "finalized": True,
                    "source_event_hash": source_event_hash(group),
                }
            )
        return windows

    def _baseline_state(self, events: list[TelemetryEvent]) -> dict[str, Any]:
        state: dict[str, dict[str, list[str]]] = {}
        for event in sorted(events, key=lambda item: (item.timestamp, item.event_id)):
            key = f"{event.synthetic}:{event.user_id}:{event.host_id}"
            current = state.setdefault(key, {"processes": [], "remotes": []})
            if event.event_type == EventType.PROCESS:
                name = str(event.payload.get("process_name", ""))
                if name and name not in current["processes"]:
                    current["processes"].append(name)
            if event.event_type == EventType.NETWORK:
                remote = f"{event.payload.get('remote_address')}:{event.payload.get('remote_port')}"
                if remote not in current["remotes"]:
                    current["remotes"].append(remote)
        return state


def quality_for_window(
    events: list[TelemetryEvent],
    *,
    dataset_kind: str,
    window_start: datetime,
    window_end: datetime,
    sessions: list[dict[str, Any]],
) -> dict[str, Any]:
    counts = Counter(event.event_type for event in events)
    reasons: list[str] = []
    heartbeat_coverage = 1.0 if dataset_kind == "synthetic" else _heartbeat_coverage(
        sessions,
        window_start,
        window_end,
    )
    if dataset_kind == "synthetic":
        status = "good" if events else "insufficient"
        if not events:
            reasons.append("no synthetic telemetry in window")
    else:
        has_process = counts[EventType.PROCESS] > 0
        has_metrics = counts[EventType.SYSTEM_METRICS] > 0
        has_network = counts[EventType.NETWORK] > 0
        if heartbeat_coverage <= 0:
            status = "insufficient"
            reasons.append("no collection heartbeat covers window")
        elif has_process and has_metrics and heartbeat_coverage >= 0.8:
            status = "good"
            if not has_network:
                status = "degraded"
                reasons.append("network collector coverage missing")
        elif has_process or has_metrics:
            status = "degraded"
            reasons.append("partial core collector coverage")
        else:
            status = "insufficient"
            reasons.append("missing process and system metrics telemetry")
        if counts[EventType.AUTHENTICATION] == 0:
            reasons.append("authentication telemetry absent or optional")
    gap = (1.0 - heartbeat_coverage) * (window_end - window_start).total_seconds()
    return {
        "status": status,
        "reasons": reasons or ["quality checks passed"],
        "heartbeat_coverage": round(heartbeat_coverage, 4),
        "gap_duration_seconds": round(max(0.0, gap), 4),
    }


def _heartbeat_coverage(
    sessions: list[dict[str, Any]],
    window_start: datetime,
    window_end: datetime,
) -> float:
    covered = 0.0
    for session in sessions:
        if session.get("collection_mode") != "real":
            continue
        start = datetime.fromisoformat(str(session["started_at"])).astimezone(UTC)
        stop_raw = session.get("stopped_at") or session.get("last_heartbeat_at")
        if not stop_raw:
            continue
        stop = datetime.fromisoformat(str(stop_raw)).astimezone(UTC)
        overlap_start = max(start, window_start)
        overlap_end = min(stop, window_end)
        if overlap_end > overlap_start:
            covered += (overlap_end - overlap_start).total_seconds()
    total = (window_end - window_start).total_seconds()
    return min(1.0, covered / total) if total > 0 else 0.0
