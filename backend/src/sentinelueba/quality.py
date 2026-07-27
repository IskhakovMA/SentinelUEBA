from __future__ import annotations

from collections import Counter
from datetime import UTC, datetime
from typing import Any
from uuid import uuid4

from sentinelueba.storage.sqlite import SQLiteStorage


class DataQualityService:
    def __init__(self, storage: SQLiteStorage) -> None:
        self.storage = storage

    def summary(self) -> dict[str, Any]:
        events = self.storage.list_event_rows()
        event_objects = [row["event"] for row in events]
        windows = self.storage.list_feature_windows()
        by_type = Counter(event.event_type.value for event in event_objects)
        by_collector = Counter(
            str(row.get("collector_id") or row["event"].source) for row in events
        )
        profiles = sorted({f"{event.user_id}:{event.host_id}" for event in event_objects})
        timestamps = [event.timestamp for event in event_objects]
        state = {
            "synthetic": self.storage.get_materialization_state("synthetic"),
            "real": self.storage.get_materialization_state("real"),
        }
        quality_counts = Counter(window["quality_status"] for window in windows)
        usable_real_windows = [
            window
            for window in windows
            if window["dataset_kind"] == "real" and window["quality_status"] == "good"
        ]
        summary = {
            "event_counts_by_type": dict(by_type),
            "event_counts_by_collector": dict(by_collector),
            "quarantine": self.storage.quarantine_summary(),
            "duplicate_events": 0,
            "time_range": {
                "start": min(timestamps).isoformat() if timestamps else None,
                "end": max(timestamps).isoformat() if timestamps else None,
            },
            "gaps": self.storage.collection_progress()["gaps"],
            "collector_coverage": self._collector_coverage(windows),
            "window_quality": dict(quality_counts),
            "usable_coverage_seconds": len(usable_real_windows) * 15 * 60,
            "profiles": profiles,
            "schema_versions": sorted(
                str(row["event_schema_version"])
                for row in events
                if row.get("event_schema_version")
            ),
            "late_events": 0,
            "last_materialized_window": max(
                (window["window_end"] for window in windows),
                default=None,
            ),
            "watermark": {
                kind: value.get("watermark") if value else None
                for kind, value in state.items()
            },
            "readiness": {
                "synthetic_snapshot": any(
                    window["dataset_kind"] == "synthetic"
                    and window["quality_status"] in {"good", "degraded"}
                    for window in windows
                ),
                "real_snapshot": len(usable_real_windows) >= 96,
            },
            "collection_progress": self.storage.collection_progress(),
            "dataset_snapshots": {
                "synthetic": self.storage.list_dataset_snapshots("synthetic")[:1],
                "real": self.storage.list_dataset_snapshots("real")[:1],
            },
        }
        self.storage.record_data_quality_run(str(uuid4()), "all", summary)
        return summary

    def _collector_coverage(self, windows: list[dict[str, Any]]) -> dict[str, Any]:
        by_kind: dict[str, list[float]] = {"synthetic": [], "real": []}
        for window in windows:
            by_kind.setdefault(window["dataset_kind"], []).append(
                float(window["collector_coverage"].get("heartbeat_coverage", 0.0))
            )
        return {
            kind: {
                "windows": len(values),
                "avg_heartbeat_coverage": sum(values) / len(values) if values else 0.0,
            }
            for kind, values in by_kind.items()
        }


class RetentionService:
    def __init__(
        self,
        storage: SQLiteStorage,
        *,
        raw_real_days: int = 30,
        quarantine_days: int = 30,
    ) -> None:
        self.storage = storage
        self.raw_real_days = raw_real_days
        self.quarantine_days = quarantine_days

    def preview(self) -> dict[str, Any]:
        cutoff = datetime.now(UTC) - self._retention_delta()
        return self.storage.retention_preview(cutoff)

    def apply(self) -> dict[str, Any]:
        cutoff = datetime.now(UTC) - self._retention_delta()
        return self.storage.retention_apply(cutoff)

    def _retention_delta(self) -> Any:
        from datetime import timedelta

        return timedelta(days=min(self.raw_real_days, self.quarantine_days))
