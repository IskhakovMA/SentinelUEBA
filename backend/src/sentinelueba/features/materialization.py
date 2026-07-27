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
CORE_SYSTEM_COLLECTOR = "windows.system_metrics.psutil"
CORE_PROCESS_COLLECTOR = "windows.process.psutil"
RECOMMENDED_NETWORK_COLLECTOR = "windows.network.psutil"


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
        new_events = []
        new_observations: list[dict[str, Any]] = []
        incremental = state is not None and not rebuild
        if state is not None and not rebuild:
            new_events = self.storage.list_event_rows(
                synthetic=synthetic,
                ingested_after=state.get("last_ingested_at"),
                after_event_id=state.get("last_event_id"),
            )
            if dataset_kind == "real":
                new_observations = self.storage.list_collector_observations(
                    since=state.get("last_observation_at")
                )
            if not new_events and not new_observations:
                return self._no_op_result(dataset_kind, state)

        if state is not None and not rebuild:
            assert state is not None
            affected_start, bounded_end, late_within, late_outside = self._affected_range(
                dataset_kind,
                state,
                rebuild,
                new_events,
                new_observations,
                [],
                [],
            )
            affected_events = self.storage.list_event_rows(
                synthetic=synthetic,
                start=affected_start,
                end=bounded_end,
            )
            observation_start = affected_start - timedelta(minutes=self.window_minutes)
            affected_observations = (
                self.storage.list_collector_observations(
                    start=observation_start,
                    end=bounded_end,
                )
                if dataset_kind == "real"
                else []
            )
            baseline = self.storage.feature_novelty_baseline(
                synthetic=synthetic,
                before=affected_start,
            )
        else:
            affected_events = self.storage.list_event_rows(synthetic=synthetic)
            affected_observations = (
                self.storage.list_collector_observations() if dataset_kind == "real" else []
            )
            if not affected_events and not affected_observations:
                if rebuild:
                    self.storage.delete_feature_windows(dataset_kind)
                self._update_state(
                    dataset_kind,
                    event_rows=[],
                    observations=[],
                    rebuilt=rebuild,
                    late_within=0,
                    late_outside=0,
                    previous_state=state,
                    baseline_state=None,
                )
                return {
                    "dataset_kind": dataset_kind,
                    "processed_events": 0,
                    "processed_observations": 0,
                    "upserted_windows": 0,
                    "deleted_windows": 0,
                    "watermark": None,
                    "event_time_watermark": None,
                    "rebuild": rebuild,
                }
            affected_start, bounded_end, late_within, late_outside = self._affected_range(
                dataset_kind,
                state,
                rebuild,
                [],
                [],
                affected_events,
                affected_observations,
            )
            baseline = {}

        if not affected_events and not affected_observations:
            if rebuild:
                self.storage.delete_feature_windows(dataset_kind)
            self._update_state(
                dataset_kind,
                event_rows=new_events,
                observations=new_observations,
                rebuilt=rebuild,
                late_within=late_within,
                late_outside=late_outside,
                previous_state=state,
                baseline_state=None,
            )
            updated_state = self.storage.get_materialization_state(dataset_kind) or {}
            return {
                "dataset_kind": dataset_kind,
                "processed_events": 0,
                "processed_observations": 0,
                "upserted_windows": 0,
                "deleted_windows": 0,
                "watermark": updated_state.get("watermark"),
                "event_time_watermark": updated_state.get("event_time_watermark"),
                "rebuild": rebuild,
                "late_event_interval_minutes": self.late_event_minutes,
                "late_events_within_policy": late_within,
                "late_events_outside_policy": late_outside,
                "window_size_minutes": self.window_minutes,
            }
        windows = self._build_windows(
            [row["event"] for row in affected_events],
            dataset_kind=dataset_kind,
            from_start=affected_start,
            before_start=bounded_end,
            observations=affected_observations,
            baseline=baseline,
        )
        state_args = self._state_arguments(
            dataset_kind=dataset_kind,
            event_rows=affected_events if not incremental else new_events,
            observations=affected_observations if not incremental else new_observations,
            rebuilt=rebuild,
            late_within=late_within,
            late_outside=late_outside,
            previous_state=state,
            baseline_state=(
                self._serializable_baseline(baseline)
                if incremental
                else self._baseline_state([row["event"] for row in affected_events])
            ),
        )
        deleted, upserted = self.storage.replace_feature_windows_and_materialization_state(
            dataset_kind,
            windows=windows,
            state=state_args,
            from_start=None if rebuild else affected_start,
            before_start=None if rebuild or bounded_end is None else bounded_end,
        )
        updated_state = self.storage.get_materialization_state(dataset_kind) or {}
        return {
            "dataset_kind": dataset_kind,
            "processed_events": len(new_events) if incremental else len(affected_events),
            "processed_observations": len(new_observations)
            if incremental
            else len(affected_observations),
            "upserted_windows": upserted,
            "deleted_windows": deleted,
            "watermark": updated_state.get("watermark"),
            "event_time_watermark": updated_state.get("event_time_watermark"),
            "rebuild": rebuild,
            "late_event_interval_minutes": self.late_event_minutes,
            "late_events_within_policy": late_within,
            "late_events_outside_policy": late_outside,
            "window_size_minutes": self.window_minutes,
        }

    def status(self) -> dict[str, Any]:
        return {
            "synthetic": self.storage.get_materialization_state("synthetic"),
            "real": self.storage.get_materialization_state("real"),
            "windows": self.storage.feature_window_summary(),
        }

    def _no_op_result(self, dataset_kind: str, state: dict[str, Any]) -> dict[str, Any]:
        return {
            "dataset_kind": dataset_kind,
            "processed_events": 0,
            "processed_observations": 0,
            "upserted_windows": 0,
            "deleted_windows": 0,
            "watermark": state.get("watermark"),
            "event_time_watermark": state.get("event_time_watermark"),
            "rebuild": False,
            "late_event_interval_minutes": self.late_event_minutes,
            "late_events_within_policy": 0,
            "late_events_outside_policy": 0,
            "window_size_minutes": self.window_minutes,
        }

    def _affected_range(
        self,
        dataset_kind: str,
        state: dict[str, Any] | None,
        rebuild: bool,
        new_events: list[dict[str, Any]],
        new_observations: list[dict[str, Any]],
        all_events: list[dict[str, Any]],
        all_observations: list[dict[str, Any]],
    ) -> tuple[datetime, datetime | None, int, int]:
        if rebuild or not state:
            timestamps = [row["event"].timestamp for row in all_events]
            timestamps.extend(
                datetime.fromisoformat(str(row["observed_at"])).astimezone(UTC)
                for row in all_observations
            )
            start = align_window_start(min(timestamps), self.window_minutes)
            return start, None, 0, 0

        previous_watermark_raw = state.get("event_time_watermark") or state.get("watermark")
        previous_watermark = (
            datetime.fromisoformat(str(previous_watermark_raw)).astimezone(UTC)
            if previous_watermark_raw
            else None
        )
        policy_boundary = (
            previous_watermark - timedelta(minutes=self.late_event_minutes)
            if previous_watermark is not None
            else None
        )
        affected: list[datetime] = []
        late_within = 0
        late_outside = 0
        unbounded = False
        for row in new_events:
            event = row["event"]
            if policy_boundary is not None and event.timestamp < policy_boundary:
                late_outside += 1
                self.storage.record_late_event(
                    dataset_kind=dataset_kind,
                    event_id=event.event_id,
                    event_timestamp=event.timestamp,
                    ingested_at=str(row["ingested_at"]),
                    policy_boundary=policy_boundary,
                    within_policy=False,
                )
                continue
            if previous_watermark is not None and event.timestamp < previous_watermark:
                late_within += 1
                unbounded = True
                if policy_boundary is not None:
                    self.storage.record_late_event(
                        dataset_kind=dataset_kind,
                        event_id=event.event_id,
                        event_timestamp=event.timestamp,
                        ingested_at=str(row["ingested_at"]),
                        policy_boundary=policy_boundary,
                        within_policy=True,
                    )
            affected.append(align_window_start(event.timestamp, self.window_minutes))
        for row in new_observations:
            observed_at = datetime.fromisoformat(str(row["observed_at"])).astimezone(UTC)
            affected.append(align_window_start(observed_at, self.window_minutes))
        if not affected:
            current = datetime.now(UTC)
            start = align_window_start(current, self.window_minutes)
            return start, start, late_within, late_outside
        start = min(affected)
        end = None if unbounded else max(affected) + timedelta(minutes=self.window_minutes)
        return start, end, late_within, late_outside

    def _build_windows(
        self,
        events: list[TelemetryEvent],
        *,
        dataset_kind: str,
        from_start: datetime,
        before_start: datetime | None,
        observations: list[dict[str, Any]],
        baseline: dict[tuple[str, str], dict[str, set[str]]],
    ) -> list[dict[str, Any]]:
        grouped = group_events_by_profile_window(events, self.window_minutes)
        seen_processes: dict[tuple[str, str], set[str]] = defaultdict(set)
        seen_remotes: dict[tuple[str, str], set[str]] = defaultdict(set)
        for key, baseline_values in baseline.items():
            seen_processes[key].update(baseline_values.get("processes", set()))
            seen_remotes[key].update(baseline_values.get("remotes", set()))
        real_keys = self._real_window_keys(observations) if dataset_kind == "real" else set()
        all_keys = set(grouped) | real_keys
        windows: list[dict[str, Any]] = []
        for user_id, host_id, window_start in sorted(all_keys, key=lambda item: item[2]):
            key = (user_id, host_id)
            group = grouped.get((user_id, host_id, window_start), [])
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
            if before_start is not None and window_start >= before_start:
                continue
            quality = quality_for_window(
                group,
                dataset_kind=dataset_kind,
                window_start=window_start,
                window_end=window_end,
                observations=observations,
                user_id=user_id,
                host_id=host_id,
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
                        "collector_coverage": quality["collector_coverage"],
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

    def _real_window_keys(
        self,
        observations: list[dict[str, Any]],
    ) -> set[tuple[str, str, datetime]]:
        keys: set[tuple[str, str, datetime]] = set()
        for row in observations:
            if not row.get("user_id") or not row.get("host_id"):
                continue
            observed_at = datetime.fromisoformat(str(row["observed_at"])).astimezone(UTC)
            keys.add(
                (
                    str(row["user_id"]),
                    str(row["host_id"]),
                    align_window_start(observed_at, self.window_minutes),
                )
            )
        return keys

    def _update_state(
        self,
        dataset_kind: str,
        *,
        event_rows: list[dict[str, Any]],
        observations: list[dict[str, Any]],
        rebuilt: bool,
        late_within: int,
        late_outside: int,
        previous_state: dict[str, Any] | None,
        baseline_state: dict[str, Any] | None,
    ) -> None:
        self.storage.upsert_materialization_state(
            **self._state_arguments(
                dataset_kind=dataset_kind,
                event_rows=event_rows,
                observations=observations,
                rebuilt=rebuilt,
                late_within=late_within,
                late_outside=late_outside,
                previous_state=previous_state,
                baseline_state=baseline_state,
            )
        )

    def _state_arguments(
        self,
        *,
        dataset_kind: str,
        event_rows: list[dict[str, Any]],
        observations: list[dict[str, Any]],
        rebuilt: bool,
        late_within: int,
        late_outside: int,
        previous_state: dict[str, Any] | None,
        baseline_state: dict[str, Any] | None,
    ) -> dict[str, Any]:
        latest_event_row = max(
            event_rows,
            key=lambda row: (str(row["ingested_at"]), row["event"].event_id),
            default=None,
        )
        previous_watermark = _parse_optional_time(
            previous_state.get("event_time_watermark") if previous_state else None
        )
        current_watermark = max((row["event"].timestamp for row in event_rows), default=None)
        event_watermark = max(
            [value for value in [previous_watermark, current_watermark] if value is not None],
            default=None,
        )
        last_observation_at = max(
            (str(row["observed_at"]) for row in observations),
            default=previous_state.get("last_observation_at") if previous_state else None,
        )
        if baseline_state is not None:
            state_baseline = baseline_state
        elif previous_state is not None and isinstance(previous_state.get("baseline_state"), dict):
            state_baseline = previous_state["baseline_state"]
        else:
            state_baseline = {}
        return {
            "dataset_kind": dataset_kind,
            "watermark": event_watermark,
            "event_time_watermark": event_watermark,
            "last_ingested_at": str(latest_event_row["ingested_at"])
            if latest_event_row
            else (previous_state.get("last_ingested_at") if previous_state else None),
            "last_event_id": latest_event_row["event"].event_id
            if latest_event_row
            else (previous_state.get("last_event_id") if previous_state else None),
            "last_observation_at": last_observation_at,
            "late_events_within_policy": late_within,
            "late_events_outside_policy": late_outside,
            "late_event_interval_minutes": self.late_event_minutes,
            "window_size_minutes": self.window_minutes,
            "baseline_state": state_baseline,
            "rebuilt": rebuilt,
        }

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

    def _serializable_baseline(
        self,
        baseline: dict[tuple[str, str], dict[str, set[str]]],
    ) -> dict[str, dict[str, list[str]]]:
        return {
            f"{user_id}:{host_id}": {
                "processes": sorted(values.get("processes", set())),
                "remotes": sorted(values.get("remotes", set())),
            }
            for (user_id, host_id), values in baseline.items()
        }


def quality_for_window(
    events: list[TelemetryEvent],
    *,
    dataset_kind: str,
    window_start: datetime,
    window_end: datetime,
    observations: list[dict[str, Any]],
    user_id: str,
    host_id: str,
) -> dict[str, Any]:
    reasons: list[str] = []
    if dataset_kind == "synthetic":
        status = "good" if events else "insufficient"
        return {
            "status": status,
            "reasons": ["quality checks passed"] if events else ["no synthetic telemetry"],
            "collector_coverage": {},
            "heartbeat_coverage": 1.0 if events else 0.0,
            "gap_duration_seconds": 0.0 if events else (window_end - window_start).total_seconds(),
        }

    coverage = collector_coverage_for_window(
        observations,
        window_start=window_start,
        window_end=window_end,
        user_id=user_id,
        host_id=host_id,
    )
    system_cov = coverage.get(CORE_SYSTEM_COLLECTOR, 0.0)
    process_cov = coverage.get(CORE_PROCESS_COLLECTOR, 0.0)
    network_cov = coverage.get(RECOMMENDED_NETWORK_COLLECTOR, 0.0)
    heartbeat_coverage = max(coverage.values(), default=0.0)
    if heartbeat_coverage <= 0:
        status = "insufficient"
        reasons.append("no collector observations cover window")
    elif system_cov >= 0.8 and process_cov >= 0.8:
        status = "good"
        if network_cov < 0.8:
            status = "degraded"
            reasons.append("network collector coverage below 80 percent")
    elif system_cov >= 0.5 and process_cov >= 0.5:
        status = "degraded"
        reasons.append("core collector coverage is partial")
    else:
        status = "insufficient"
        reasons.append("system metrics or process collector coverage is insufficient")
    if CORE_SYSTEM_COLLECTOR not in coverage:
        reasons.append("system metrics collector did not poll")
    if CORE_PROCESS_COLLECTOR not in coverage:
        reasons.append("process collector did not poll")
    total = (window_end - window_start).total_seconds()
    gap = (1.0 - heartbeat_coverage) * total
    return {
        "status": status,
        "reasons": reasons or ["quality checks passed"],
        "collector_coverage": coverage,
        "heartbeat_coverage": round(heartbeat_coverage, 4),
        "gap_duration_seconds": round(max(0.0, gap), 4),
    }


def collector_coverage_for_window(
    observations: list[dict[str, Any]],
    *,
    window_start: datetime,
    window_end: datetime,
    user_id: str,
    host_id: str,
) -> dict[str, float]:
    by_collector: dict[str, float] = defaultdict(float)
    total = (window_end - window_start).total_seconds()
    if total <= 0:
        return {}
    for row in observations:
        if row.get("user_id") != user_id or row.get("host_id") != host_id:
            continue
        if not bool(row.get("successful_poll")):
            continue
        observed_at = datetime.fromisoformat(str(row["observed_at"])).astimezone(UTC)
        interval = max(1.0, float(row.get("configured_interval_seconds") or 1.0))
        start = observed_at
        end = observed_at + timedelta(seconds=interval)
        overlap_start = max(start, window_start)
        overlap_end = min(end, window_end)
        if overlap_end > overlap_start:
            by_collector[str(row["collector_id"])] += (
                overlap_end - overlap_start
            ).total_seconds()
    return {
        collector_id: round(min(1.0, covered / total), 4)
        for collector_id, covered in by_collector.items()
    }


def _parse_optional_time(value: object) -> datetime | None:
    if not value:
        return None
    return datetime.fromisoformat(str(value)).astimezone(UTC)
