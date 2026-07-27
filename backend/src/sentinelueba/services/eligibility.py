from __future__ import annotations

from typing import Any

from sentinelueba.features.materialization import CORE_PROCESS_COLLECTOR, CORE_SYSTEM_COLLECTOR
from sentinelueba.features.windows import FEATURE_SCHEMA_VERSION
from sentinelueba.storage.sqlite import SQLiteStorage


class EligibilityService:
    def __init__(self, storage: SQLiteStorage) -> None:
        self.storage = storage

    def training_eligibility(self, dataset_kind: str = "real") -> dict[str, object]:
        windows = self.storage.list_feature_windows(dataset_kind=dataset_kind)
        if dataset_kind == "synthetic":
            eligible = len(windows) >= 12
            return {
                "dataset_kind": dataset_kind,
                "eligible": eligible,
                "reason": "ready" if eligible else "not enough synthetic windows",
                "windows": len(windows),
            }
        progress = self.storage.collection_progress()
        good_windows = [window for window in windows if window["quality_status"] == "good"]
        profiles = {(window["user_id"], window["host_id"]) for window in windows}
        usable_seconds = len(good_windows) * 15 * 60
        cumulative_seconds = float(progress["cumulative_collected_seconds"])
        enough_duration = cumulative_seconds >= 24 * 60 * 60
        enough_usable = usable_seconds >= 24 * 60 * 60
        enough_windows = len(good_windows) >= 96
        single_profile = len(profiles) == 1 if profiles else False
        compatible_schema = all(
            window["feature_schema_version"] == FEATURE_SCHEMA_VERSION for window in windows
        )
        synthetic_mixed = any(window["dataset_kind"] != "real" for window in windows)
        avg_system = self._average_collector_coverage(good_windows, CORE_SYSTEM_COLLECTOR)
        avg_process = self._average_collector_coverage(good_windows, CORE_PROCESS_COLLECTOR)
        enough_system_coverage = avg_system >= 0.8
        enough_process_coverage = avg_process >= 0.8
        duration_covers_usable = cumulative_seconds >= usable_seconds
        reason = "ready"
        if not enough_duration:
            reason = "requires 24 cumulative hours of real collection"
        elif not enough_usable:
            reason = "requires 24 cumulative hours of usable real coverage"
        elif not enough_windows:
            reason = "not enough good real feature windows"
        elif not single_profile:
            reason = "requires exactly one user+host profile"
        elif not enough_system_coverage:
            reason = "system metrics coverage is insufficient"
        elif not enough_process_coverage:
            reason = "process collector coverage is insufficient"
        elif not compatible_schema:
            reason = "feature schema is incompatible"
        elif synthetic_mixed:
            reason = "real eligibility cannot include synthetic windows"
        elif not duration_covers_usable:
            reason = "cumulative duration is less than usable coverage"
        eligible = (
            enough_duration
            and enough_usable
            and enough_windows
            and single_profile
            and enough_system_coverage
            and enough_process_coverage
            and compatible_schema
            and not synthetic_mixed
            and duration_covers_usable
        )
        return {
            "dataset_kind": dataset_kind,
            "eligible": eligible,
            "reason": reason,
            "windows": len(windows),
            "good_windows": len(good_windows),
            "degraded_windows": sum(
                1 for window in windows if window["quality_status"] == "degraded"
            ),
            "insufficient_windows": sum(
                1 for window in windows if window["quality_status"] == "insufficient"
            ),
            "cumulative_collected_seconds": progress["cumulative_collected_seconds"],
            "usable_coverage_seconds": usable_seconds,
            "usable_coverage_hours": usable_seconds / 3600,
            "avg_system_metrics_coverage": avg_system,
            "avg_process_coverage": avg_process,
            "longest_continuous_collection_seconds": progress[
                "longest_continuous_session_seconds"
            ],
            "strict_continuous_24h_validated": progress["strict_continuous_24h_validated"],
        }

    def readiness(self) -> dict[str, Any]:
        synthetic = self.training_eligibility("synthetic")
        real = self.training_eligibility("real")
        return {
            "synthetic_snapshot": bool(synthetic["eligible"]),
            "real_snapshot": bool(real["eligible"]),
            "synthetic": synthetic,
            "real": real,
        }

    def _average_collector_coverage(
        self,
        windows: list[dict[str, Any]],
        collector_id: str,
    ) -> float:
        if not windows:
            return 0.0
        values = []
        for window in windows:
            coverage = window.get("collector_coverage", {})
            if isinstance(coverage, dict):
                per_collector = coverage.get("collector_coverage", {})
                if isinstance(per_collector, dict):
                    values.append(float(per_collector.get(collector_id, 0.0)))
        return sum(values) / len(windows) if values else 0.0
