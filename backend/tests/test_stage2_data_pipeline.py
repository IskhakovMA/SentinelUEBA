from __future__ import annotations

import json
import sqlite3
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pyarrow as pa
import pyarrow.parquet as pq
import pytest
from fastapi.testclient import TestClient
from typer.testing import CliRunner

from sentinelueba.api.main import app
from sentinelueba.cli import app as cli_app
from sentinelueba.collectors.network import NetworkCollector, NetworkSnapshot
from sentinelueba.collectors.process import ProcessCollector, ProcessSnapshot
from sentinelueba.collectors.system_metrics import SystemMetricsCollector
from sentinelueba.collectors.windows_auth import WindowsAuthCollector
from sentinelueba.config import Settings
from sentinelueba.datasets import SnapshotVerificationError
from sentinelueba.datasets import snapshots as snapshot_module
from sentinelueba.domain.events import EventType, TelemetryEvent, deterministic_event_id
from sentinelueba.features.materialization import FeatureMaterializer
from sentinelueba.features.windows import align_window_start
from sentinelueba.ml.autoencoder import model_info
from sentinelueba.services.pipeline import DemoPipeline
from sentinelueba.storage.sqlite import SchemaIntegrityError, SQLiteStorage
from sentinelueba.validation import validate_event


def settings(tmp_path: Path) -> Settings:
    return Settings(
        data_dir=tmp_path / "data",
        database_path=tmp_path / "data" / "stage2.sqlite3",
        model_dir=tmp_path / "model",
    )


@pytest.mark.parametrize(
    ("event_type", "payload"),
    [
        (EventType.PROCESS, {"process_name": "editor.exe", "pid": 10}),
        (EventType.NETWORK, {"remote_address": "198.51.100.10", "remote_port": 443}),
        (EventType.SYSTEM_METRICS, {"cpu_percent": 10.0, "ram_percent": 45.0}),
        (EventType.AUTHENTICATION, {"result": "success", "method": "local"}),
    ],
)
def test_payload_validation_accepts_each_event_type(
    event_type: EventType,
    payload: dict[str, object],
) -> None:
    result = validate_event(event(1, event_type, payload))
    assert not hasattr(result, "reason")


def test_payload_validation_rejects_unknown_fields_and_quarantines(tmp_path: Path) -> None:
    store = SQLiteStorage(tmp_path / "events.sqlite3")
    store.initialize()
    invalid = event(
        1,
        EventType.SYSTEM_METRICS,
        {"cpu_percent": float("nan"), "ram_percent": 40.0},
    )
    assert store.insert_events([invalid]) == 0
    summary = store.quarantine_summary()
    assert summary["count"] == 1


@pytest.mark.parametrize(
    ("event_type", "payload"),
    [
        (
            EventType.PROCESS,
            {"process_name": "editor.exe", "unexpected": "value"},
        ),
        (
            EventType.NETWORK,
            {"remote_address": "198.51.100.10", "remote_port": 443, "unexpected": "value"},
        ),
        (
            EventType.SYSTEM_METRICS,
            {"cpu_percent": 10.0, "ram_percent": 20.0, "unexpected": "value"},
        ),
        (
            EventType.AUTHENTICATION,
            {"result": "success", "method": "local", "unexpected": "value"},
        ),
    ],
)
def test_unknown_payload_fields_are_quarantined_without_forbidden_values(
    tmp_path: Path,
    event_type: EventType,
    payload: dict[str, object],
) -> None:
    store = SQLiteStorage(tmp_path / f"unknown-{event_type.value}.sqlite3")
    store.initialize()
    assert store.insert_events([event(1, event_type, payload)]) == 0
    with store.connect() as conn:
        row = conn.execute(
            "SELECT reason, safe_event_json FROM quarantined_events"
        ).fetchone()
    assert row is not None
    assert "unknown" in row["reason"] or "forbidden" in row["reason"]
    assert "unexpected" not in row["safe_event_json"]
    assert "value" not in row["safe_event_json"]


def test_real_stage1_collector_payloads_are_accepted(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store = SQLiteStorage(tmp_path / "collector-payloads.sqlite3")
    store.initialize()
    ts = datetime(2026, 1, 1, 10, 0, tzinfo=UTC)
    process = ProcessCollector("user-a", "host-a")._event(
        ts,
        "started",
        ProcessSnapshot(10, 1.0, "editor.exe", "C:/Tools/editor.exe", None, None),
    )
    network = NetworkCollector("user-a", "host-a")._event(
        ts,
        "opened",
        NetworkSnapshot("tcp", "ESTABLISHED", "198.51.100.20", 443, 50000, 10, "editor.exe"),
    )
    auth = WindowsAuthCollector("user-a", "host-a").event_from_fixture(
        {
            "EventID": 4625,
            "RecordID": 101,
            "LogonType": 2,
            "TargetUserName": "analyst",
            "TargetDomainName": "DEMO",
            "Status": "0xC000006D",
            "SubStatus": "0xC000006A",
        },
        ts,
    )
    monkeypatch.setattr("psutil.cpu_percent", lambda interval=None: 12.0)
    monkeypatch.setattr("psutil.virtual_memory", lambda: type("Mem", (), {"percent": 45.0})())
    monkeypatch.setattr("psutil.disk_usage", lambda path: type("Disk", (), {"percent": 55.0})())
    monkeypatch.setattr("psutil.boot_time", lambda: 1_700_000_000.0)
    monkeypatch.setattr(
        "psutil.net_io_counters",
        lambda: type("Net", (), {"bytes_sent": 100, "bytes_recv": 200})(),
    )
    metrics = SystemMetricsCollector("user-a", "host-a").collect()[0]
    assert auth is not None
    assert store.insert_events([process, network, auth, metrics]) == 4
    rows = store.list_event_rows(synthetic=False)
    assert len(rows) == 4
    assert {row["validation_status"] for row in rows} == {"accepted"}
    auth_row = next(row for row in rows if row["event"].event_type == EventType.AUTHENTICATION)
    assert auth_row["event"].payload["target_domain_name"] == "DEMO"
    assert auth_row["event"].payload["status"] == "0xC000006D"
    assert auth_row["event"].payload["sub_status"] == "0xC000006A"
    assert store.quarantine_summary()["count"] == 0


@pytest.mark.parametrize(
    ("event_type", "payload"),
    [
        (EventType.PROCESS, {"action": "created", "process_name": "bad.exe"}),
        (EventType.NETWORK, {"action": "opened", "remote_address": "x", "remote_port": 70000}),
        (EventType.SYSTEM_METRICS, {"cpu_percent": 101.0, "ram_percent": 1.0}),
        (EventType.AUTHENTICATION, {"action": "logon", "result": "success"}),
    ],
)
def test_invalid_payload_for_each_event_type_is_quarantined(
    tmp_path: Path,
    event_type: EventType,
    payload: dict[str, object],
) -> None:
    store = SQLiteStorage(tmp_path / f"invalid-{event_type.value}.sqlite3")
    store.initialize()
    assert store.insert_events([event(1, event_type, payload, synthetic=False)]) == 0
    assert store.quarantine_summary()["count"] == 1


@pytest.mark.parametrize("version", [1, 2, 3, 4, 5])
def test_historical_schema_migrations_to_v6(tmp_path: Path, version: int) -> None:
    db = tmp_path / f"v{version}.sqlite3"
    create_historical_database(db, version)
    store = SQLiteStorage(db)
    store.initialize()
    assert store.status()["schema_version"] == 6
    assert store.status()["event_count"] == 1
    columns = {
        row[1] for row in sqlite3.connect(db).execute("PRAGMA table_info(telemetry_events)")
    }
    assert {"ingested_at", "collection_session_id", "payload_hash"}.issubset(columns)
    assert "collector_observations" in table_names(db)
    state_columns = {
        row[1]
        for row in sqlite3.connect(db).execute(
            "PRAGMA table_info(feature_materialization_state)"
        )
    }
    assert "last_observation_id" in state_columns


def test_fresh_schema_initializes_to_v6(tmp_path: Path) -> None:
    store = SQLiteStorage(tmp_path / "fresh.sqlite3")
    store.initialize()
    assert store.status()["schema_version"] == 6
    assert "collector_observations" in table_names(store.database_path)


def test_repeated_initialize_v6_runs_no_migrations_or_event_updates(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store = SQLiteStorage(tmp_path / "repeat.sqlite3")
    store.initialize()
    original = event(1, EventType.SYSTEM_METRICS, {"cpu_percent": 10.0, "ram_percent": 40.0})
    assert store.insert_events([original]) == 1
    before = sqlite3.connect(store.database_path).execute(
        "SELECT ingested_at, payload_hash, payload_json FROM telemetry_events WHERE event_id = ?",
        (original.event_id,),
    ).fetchone()

    def fail_migration(method_name: str):
        def fail(conn: sqlite3.Connection) -> None:
            pytest.fail(f"{method_name} should not run for schema v6")

        return fail

    for name in ["_apply_v1", "_apply_v2", "_apply_v3", "_apply_v4", "_apply_v5", "_apply_v6"]:
        monkeypatch.setattr(store, name, fail_migration(name))
    store.initialize()

    after = sqlite3.connect(store.database_path).execute(
        "SELECT ingested_at, payload_hash, payload_json FROM telemetry_events WHERE event_id = ?",
        (original.event_id,),
    ).fetchone()
    assert after == before


def test_v6_missing_required_table_raises_schema_integrity_error(tmp_path: Path) -> None:
    store = SQLiteStorage(tmp_path / "corrupt-v6.sqlite3")
    store.initialize()
    with sqlite3.connect(store.database_path) as conn:
        conn.execute("DROP TABLE collector_observations")
    with pytest.raises(SchemaIntegrityError, match="missing table"):
        store.initialize()


def test_deterministic_window_alignment_and_profile_isolation(tmp_path: Path) -> None:
    store = SQLiteStorage(tmp_path / "features.sqlite3")
    store.initialize()
    ts = datetime(2026, 1, 1, 10, 7, tzinfo=UTC)
    assert align_window_start(ts).isoformat() == "2026-01-01T10:00:00+00:00"
    events = [
        event(1, EventType.PROCESS, {"process_name": "a.exe"}, ts=ts, user="u1", host="h1"),
        event(
            2,
            EventType.SYSTEM_METRICS,
            {"cpu_percent": 1.0, "ram_percent": 2.0},
            ts=ts,
            user="u1",
            host="h1",
        ),
        event(3, EventType.PROCESS, {"process_name": "a.exe"}, ts=ts, user="u2", host="h1"),
        event(
            4,
            EventType.SYSTEM_METRICS,
            {"cpu_percent": 1.0, "ram_percent": 2.0},
            ts=ts,
            user="u2",
            host="h1",
        ),
    ]
    assert store.insert_events(events) == 4
    result = FeatureMaterializer(store).materialize("synthetic")
    windows = store.list_feature_windows(dataset_kind="synthetic")
    assert result["upserted_windows"] == 2
    assert {(window["user_id"], window["host_id"]) for window in windows} == {
        ("u1", "h1"),
        ("u2", "h1"),
    }


def test_synthetic_real_separation_and_idempotent_incremental_materialization(
    tmp_path: Path,
) -> None:
    store = SQLiteStorage(tmp_path / "separated.sqlite3")
    store.initialize()
    store.insert_events(
        real_profile_events(datetime(2026, 1, 1, tzinfo=UTC), windows=2, synthetic=True)
    )
    store.insert_events(
        real_profile_events(datetime(2026, 1, 2, tzinfo=UTC), windows=2, synthetic=False)
    )
    materializer = FeatureMaterializer(store)
    first = materializer.materialize("synthetic")
    second = materializer.materialize("synthetic")
    materializer.materialize("real")
    assert first["upserted_windows"] == 2
    assert second["upserted_windows"] == 0
    assert store.feature_window_summary()["synthetic"]["good"] == 2
    assert store.feature_window_summary()["real"]["insufficient"] == 2


def test_noop_incremental_materialization_does_not_touch_timestamps(tmp_path: Path) -> None:
    store = SQLiteStorage(tmp_path / "noop.sqlite3")
    store.initialize()
    start = datetime(2026, 1, 1, tzinfo=UTC)
    store.insert_events(real_profile_events(start, windows=2, synthetic=True))
    materializer = FeatureMaterializer(store)

    first = materializer.materialize("synthetic")
    windows_before = store.list_feature_windows(dataset_kind="synthetic")
    state_before = store.get_materialization_state("synthetic")
    second = materializer.materialize("synthetic")
    windows_after = store.list_feature_windows(dataset_kind="synthetic")
    state_after = store.get_materialization_state("synthetic")

    assert first["upserted_windows"] == 2
    assert second["processed_events"] == 0
    assert second["upserted_windows"] == 0
    assert second["deleted_windows"] == 0
    assert [window["updated_at"] for window in windows_after] == [
        window["updated_at"] for window in windows_before
    ]
    assert state_after == state_before


def test_incremental_new_event_after_watermark_only_materializes_new_window(
    tmp_path: Path,
) -> None:
    store = SQLiteStorage(tmp_path / "incremental-window.sqlite3")
    store.initialize()
    start = datetime(2026, 1, 1, tzinfo=UTC)
    store.insert_events(real_profile_events(start, windows=2, synthetic=True))
    materializer = FeatureMaterializer(store)
    materializer.materialize("synthetic")

    store.insert_events(
        [
            event(
                100,
                EventType.PROCESS,
                {"process_name": "new.exe"},
                ts=start + timedelta(minutes=30),
            )
        ]
    )
    result = materializer.materialize("synthetic")

    assert result["processed_events"] == 1
    assert result["upserted_windows"] == 1
    assert result["deleted_windows"] == 0
    assert len(store.list_feature_windows(dataset_kind="synthetic")) == 3


def test_incremental_materialization_reads_only_new_and_affected_ranges(
    tmp_path: Path,
) -> None:
    store = InstrumentedStorage(tmp_path / "instrumented.sqlite3")
    store.initialize()
    start = datetime(2026, 1, 1, tzinfo=UTC)
    add_session(store, start, start + timedelta(hours=1))
    add_observations(store, start, windows=3)
    store.insert_events(real_profile_events(start, windows=3, synthetic=False))
    materializer = FeatureMaterializer(store)
    materializer.materialize("real", rebuild=True)
    windows_before = store.list_feature_windows(dataset_kind="real")
    store.reset_instrumentation()

    add_observations(store, start + timedelta(minutes=45), windows=1)
    store.insert_events(
        [
            event(
                100,
                EventType.PROCESS,
                {"process_name": "new.exe"},
                ts=start + timedelta(minutes=45),
                synthetic=False,
            )
        ]
    )
    result = materializer.materialize("real")
    windows_after = store.list_feature_windows(dataset_kind="real")

    assert result["processed_events"] == 1
    assert result["processed_observations"] == 3
    assert result["upserted_windows"] == 1
    assert store.unrestricted_event_reads == 0
    assert store.unrestricted_observation_reads == 0
    assert any(call.get("start") is not None for call in store.event_row_calls)
    assert any(call.get("after_observation_id") is not None for call in store.observation_calls)
    assert any(
        call.get("overlapping") and call.get("start") is not None
        for call in store.observation_calls
    )
    before_by_start = {window["window_start"]: window for window in windows_before}
    after_by_start = {window["window_start"]: window for window in windows_after}
    for window_start, before_window in before_by_start.items():
        assert after_by_start[window_start]["updated_at"] == before_window["updated_at"]


def test_same_timestamp_observation_watermark_uses_observation_id(tmp_path: Path) -> None:
    store = SQLiteStorage(tmp_path / "same-observed-at.sqlite3")
    store.initialize()
    start = datetime(2026, 1, 1, 10, 0, tzinfo=UTC)
    add_session(store, start, start + timedelta(minutes=15))
    store.record_collector_observation(
        session_id="fixture-session",
        collector_id="windows.system_metrics.psutil",
        user_id="user-a",
        host_id="host-a",
        observed_at=start,
        status="ok",
        successful_poll=True,
        error_class=None,
        configured_interval_seconds=15 * 60,
        returned_events=0,
        saved_events=0,
    )
    materializer = FeatureMaterializer(store)

    first = materializer.materialize("real")
    first_state = store.get_materialization_state("real")
    store.record_collector_observation(
        session_id="fixture-session",
        collector_id="windows.process.psutil",
        user_id="user-a",
        host_id="host-a",
        observed_at=start,
        status="ok",
        successful_poll=True,
        error_class=None,
        configured_interval_seconds=15 * 60,
        returned_events=0,
        saved_events=0,
    )
    second = materializer.materialize("real")
    second_state = store.get_materialization_state("real")
    third = materializer.materialize("real")

    assert first["processed_observations"] == 1
    assert first_state is not None
    assert first_state["last_observation_at"] == start.isoformat()
    assert first_state["last_observation_id"] == 1
    assert second["processed_observations"] == 1
    assert second["upserted_windows"] == 1
    assert second_state is not None
    assert second_state["last_observation_at"] == start.isoformat()
    assert second_state["last_observation_id"] == 2
    assert third["processed_observations"] == 0
    assert third["upserted_windows"] == 0


def test_incremental_materialization_uses_overlapping_3600s_observation_range(
    tmp_path: Path,
) -> None:
    store = InstrumentedStorage(tmp_path / "overlap-3600.sqlite3")
    store.initialize()
    start = datetime(2026, 1, 1, 10, 0, tzinfo=UTC)
    add_session(store, start, start + timedelta(hours=1))
    add_observations(store, start, windows=1, interval_seconds=60 * 60)
    store.insert_events(real_profile_events(start, windows=3, synthetic=False))
    materializer = FeatureMaterializer(store)
    materializer.materialize("real", rebuild=True)
    store.reset_instrumentation()
    store.insert_events(
        real_profile_events(
            start + timedelta(minutes=45),
            windows=1,
            synthetic=False,
        )
    )

    result = materializer.materialize("real")
    incremental_windows = comparable_feature_windows(
        store.list_feature_windows(dataset_kind="real")
    )
    materializer.materialize("real", rebuild=True)
    rebuilt_windows = comparable_feature_windows(store.list_feature_windows(dataset_kind="real"))
    late_window = next(
        window
        for window in rebuilt_windows
        if window["window_start"] == (start + timedelta(minutes=45)).isoformat()
    )

    assert result["processed_events"] == 2
    assert result["upserted_windows"] == 1
    assert any(call.get("overlapping") for call in store.observation_calls)
    assert max(store.observation_rows_read, default=0) <= 3
    assert incremental_windows == rebuilt_windows
    assert late_window["quality_status"] == "good"


def test_incremental_materialization_respects_short_observation_interval(
    tmp_path: Path,
) -> None:
    store = SQLiteStorage(tmp_path / "overlap-5s.sqlite3")
    store.initialize()
    start = datetime(2026, 1, 1, 10, 0, tzinfo=UTC)
    add_session(store, start, start + timedelta(minutes=30))
    add_observations(store, start, windows=1, interval_seconds=5)
    store.insert_events(real_profile_events(start, windows=1, synthetic=False))
    materializer = FeatureMaterializer(store)
    materializer.materialize("real", rebuild=True)
    store.insert_events(
        real_profile_events(
            start + timedelta(minutes=15),
            windows=1,
            synthetic=False,
        )
    )

    result = materializer.materialize("real")
    incremental_windows = comparable_feature_windows(
        store.list_feature_windows(dataset_kind="real")
    )
    materializer.materialize("real", rebuild=True)
    rebuilt_windows = comparable_feature_windows(store.list_feature_windows(dataset_kind="real"))
    later_window = next(
        window
        for window in rebuilt_windows
        if window["window_start"] == (start + timedelta(minutes=15)).isoformat()
    )

    assert result["processed_events"] == 2
    assert incremental_windows == rebuilt_windows
    assert later_window["quality_status"] == "insufficient"


def test_late_event_recomputation_and_full_rebuild_equivalence(tmp_path: Path) -> None:
    store = SQLiteStorage(tmp_path / "late.sqlite3")
    store.initialize()
    start = datetime(2026, 1, 1, tzinfo=UTC)
    store.insert_events(real_profile_events(start, windows=3, synthetic=True))
    materializer = FeatureMaterializer(store)
    materializer.materialize("synthetic", rebuild=True)
    before = store.list_feature_windows(dataset_kind="synthetic")
    late = event(
        100,
        EventType.NETWORK,
        {"remote_address": "203.0.113.1", "remote_port": 443},
        ts=start + timedelta(minutes=15),
    )
    store.insert_events([late])
    materializer.materialize("synthetic")
    incremental = store.list_feature_windows(dataset_kind="synthetic")
    materializer.materialize("synthetic", rebuild=True)
    rebuilt = store.list_feature_windows(dataset_kind="synthetic")
    assert before[1]["features"]["new_remote_count"] == 0
    comparable_incremental = [
        {key: value for key, value in window.items() if key not in {"created_at", "updated_at"}}
        for window in incremental
    ]
    comparable_rebuilt = [
        {key: value for key, value in window.items() if key not in {"created_at", "updated_at"}}
        for window in rebuilt
    ]
    assert comparable_incremental == comparable_rebuilt
    assert rebuilt[1]["features"]["new_remote_count"] == 1


def test_late_event_outside_policy_is_reported_in_data_quality(tmp_path: Path) -> None:
    store = SQLiteStorage(tmp_path / "late-outside.sqlite3")
    store.initialize()
    start = datetime(2026, 1, 1, tzinfo=UTC)
    store.insert_events(real_profile_events(start, windows=8, synthetic=True))
    materializer = FeatureMaterializer(store)
    materializer.materialize("synthetic")
    store.insert_events(
        [
            event(
                100,
                EventType.NETWORK,
                {"remote_address": "203.0.113.10", "remote_port": 443},
                ts=start,
            )
        ]
    )

    result = materializer.materialize("synthetic")
    pipe = DemoPipeline(settings(tmp_path))
    pipe.storage = store
    quality = pipe.data_quality()

    assert result["late_events_outside_policy"] == 1
    assert result["upserted_windows"] == 0
    assert quality["late_events"]["outside_policy"] == 1


def test_data_quality_received_counters_and_readiness_use_shared_eligibility(
    tmp_path: Path,
) -> None:
    store = SQLiteStorage(tmp_path / "quality-counters.sqlite3")
    store.initialize()
    accepted = event(1, EventType.SYSTEM_METRICS, {"cpu_percent": 10.0, "ram_percent": 20.0})
    quarantined = event(
        2,
        EventType.SYSTEM_METRICS,
        {"cpu_percent": 10.0, "ram_percent": 20.0, "unexpected": "value"},
    )
    assert store.insert_events([accepted, accepted, quarantined]) == 1
    pipe = DemoPipeline(settings(tmp_path))
    pipe.storage = store
    quality = pipe.data_quality()
    synthetic_eligibility = pipe.training_eligibility("synthetic")
    real_eligibility = pipe.training_eligibility("real")

    assert quality["accepted_events"] == 1
    assert quality["duplicate_event_count"] == 1
    assert quality["quarantined_event_count"] == 1
    assert quality["received_events"] == 3
    assert quality["readiness"]["synthetic"] == synthetic_eligibility
    assert quality["readiness"]["real"] == real_eligibility
    assert set(quality["window_quality"]) == {"synthetic", "real"}


def test_materialization_large_dataset_rerun_has_no_duplicate_windows(tmp_path: Path) -> None:
    store = SQLiteStorage(tmp_path / "large.sqlite3")
    store.initialize()
    start = datetime(2026, 1, 1, tzinfo=UTC)
    store.insert_events(real_profile_events(start, windows=10_000, synthetic=True))
    materializer = FeatureMaterializer(store)
    first = materializer.materialize("synthetic", rebuild=True)
    second = materializer.materialize("synthetic")
    windows = store.list_feature_windows(dataset_kind="synthetic")
    assert first["processed_events"] == 20_000
    assert len(windows) == 10_000
    assert second["upserted_windows"] <= first["upserted_windows"]
    assert len({window["window_id"] for window in windows}) == len(windows)


def test_large_incremental_materialization_reads_bounded_rows(tmp_path: Path) -> None:
    store = InstrumentedStorage(tmp_path / "large-bounded.sqlite3")
    store.initialize()
    start = datetime(2026, 1, 1, tzinfo=UTC)
    store.insert_events(real_profile_events(start, windows=10_000, synthetic=True))
    materializer = FeatureMaterializer(store)
    materializer.materialize("synthetic", rebuild=True)
    store.reset_instrumentation()
    store.insert_events(
        [
            event(
                100_000,
                EventType.PROCESS,
                {"process_name": "bounded.exe"},
                ts=start + timedelta(minutes=15 * 10_000),
            )
        ]
    )

    result = materializer.materialize("synthetic")

    assert result["processed_events"] == 1
    assert result["upserted_windows"] == 1
    assert store.unrestricted_event_reads == 0
    assert max(store.event_rows_read, default=0) <= 1
    assert sum(store.event_rows_read) < 100


def test_parquet_snapshot_roundtrip_immutable_and_checksum(tmp_path: Path) -> None:
    pipe = DemoPipeline(settings(tmp_path))
    pipe.initialize()
    pipe.generate_demo_data(seed=5)
    pipe.materialize_features("synthetic")
    created = pipe.create_dataset("synthetic")
    dataset_id = str(created["dataset_id"])
    verified = pipe.verify_dataset(dataset_id)
    assert verified["verified"] is True
    matrix, manifest, rows = pipe.snapshots().load_matrix(dataset_id)
    assert matrix
    assert rows
    assert manifest["dataset_id"] == dataset_id
    parquet_path = tmp_path / "data" / "datasets" / dataset_id / "features.parquet"
    parquet_path.write_bytes(parquet_path.read_bytes() + b"corruption")
    with pytest.raises(SnapshotVerificationError):
        pipe.verify_dataset(dataset_id)


def test_snapshot_manifest_checksums_and_registry_tamper_are_rejected(tmp_path: Path) -> None:
    pipe = prepared_snapshot_pipe(tmp_path, seed=61)
    dataset_id = str(pipe.list_datasets("synthetic")["datasets"][0]["dataset_id"])
    dataset_dir = tmp_path / "data" / "datasets" / dataset_id
    manifest_path = dataset_dir / "manifest.json"
    manifest = json.loads(manifest_path.read_text())
    manifest["window_count"] = manifest["window_count"] + 1
    manifest_path.write_text(json.dumps(manifest))
    with pytest.raises(SnapshotVerificationError):
        pipe.verify_dataset(dataset_id)

    pipe = prepared_snapshot_pipe(tmp_path / "checksums", seed=62)
    dataset_id = str(pipe.list_datasets("synthetic")["datasets"][0]["dataset_id"])
    checksums_path = tmp_path / "checksums" / "data" / "datasets" / dataset_id / "checksums.sha256"
    checksums_path.write_text("0" * 64 + "  features.parquet\n")
    with pytest.raises(SnapshotVerificationError):
        pipe.verify_dataset(dataset_id)

    pipe = prepared_snapshot_pipe(tmp_path / "registry", seed=63)
    dataset_id = str(pipe.list_datasets("synthetic")["datasets"][0]["dataset_id"])
    with pipe.storage.connect() as conn:
        conn.execute(
            "UPDATE dataset_snapshots SET manifest_sha256 = ? WHERE dataset_id = ?",
            ("0" * 64, dataset_id),
        )
    with pytest.raises(SnapshotVerificationError):
        pipe.verify_dataset(dataset_id)


def test_snapshot_path_and_parquet_content_validation(tmp_path: Path) -> None:
    pipe = prepared_snapshot_pipe(tmp_path, seed=64)
    dataset_id = str(pipe.list_datasets("synthetic")["datasets"][0]["dataset_id"])
    with pytest.raises(SnapshotVerificationError):
        pipe.verify_dataset("../synthetic-20260101000000-deadbeef")

    dataset_dir = tmp_path / "data" / "datasets" / dataset_id
    table = pq.read_table(dataset_dir / "features.parquet")
    rows = table.to_pylist()
    rows[0]["dataset_kind"] = "real"
    pq.write_table(pa.Table.from_pylist(rows), dataset_dir / "features.parquet")
    with pytest.raises(SnapshotVerificationError):
        pipe.verify_dataset(dataset_id)

    pipe = prepared_snapshot_pipe(tmp_path / "nan", seed=65)
    dataset_id = str(pipe.list_datasets("synthetic")["datasets"][0]["dataset_id"])
    dataset_dir = tmp_path / "nan" / "data" / "datasets" / dataset_id
    rows = pq.read_table(dataset_dir / "features.parquet").to_pylist()
    rows[0]["process_count"] = float("nan")
    pq.write_table(pa.Table.from_pylist(rows), dataset_dir / "features.parquet")
    with pytest.raises(SnapshotVerificationError):
        pipe.verify_dataset(dataset_id)


def test_snapshot_row_index_boundaries_registry_and_missing_files_are_rejected(
    tmp_path: Path,
) -> None:
    pipe = prepared_snapshot_pipe(tmp_path, seed=68)
    dataset_id = str(pipe.list_datasets("synthetic")["datasets"][0]["dataset_id"])
    dataset_dir = tmp_path / "data" / "datasets" / dataset_id
    rows = pq.read_table(dataset_dir / "features.parquet").to_pylist()
    rows[0]["row_index"] = 99
    rewrite_snapshot_with_consistent_hashes(pipe, dataset_id, rows)
    with pytest.raises(SnapshotVerificationError, match="row_index"):
        pipe.verify_dataset(dataset_id)

    pipe = prepared_snapshot_pipe(tmp_path / "boundary", seed=69)
    dataset_id = str(pipe.list_datasets("synthetic")["datasets"][0]["dataset_id"])
    dataset_dir = tmp_path / "boundary" / "data" / "datasets" / dataset_id
    rows = pq.read_table(dataset_dir / "features.parquet").to_pylist()
    rows[0]["window_start"] = "2026-01-01T00:01:00+00:00"
    rewrite_snapshot_with_consistent_hashes(pipe, dataset_id, rows)
    with pytest.raises(SnapshotVerificationError, match="first Parquet window_start"):
        pipe.verify_dataset(dataset_id)

    pipe = prepared_snapshot_pipe(tmp_path / "registry-profile", seed=70)
    dataset_id = str(pipe.list_datasets("synthetic")["datasets"][0]["dataset_id"])
    with pipe.storage.connect() as conn:
        conn.execute(
            "UPDATE dataset_snapshots SET profile_json = ? WHERE dataset_id = ?",
            (json.dumps({"user_id": "other", "host_id": "host-a"}), dataset_id),
        )
    with pytest.raises(SnapshotVerificationError, match="SQLite profile"):
        pipe.verify_dataset(dataset_id)

    for filename in ["features.parquet", "manifest.json", "checksums.sha256"]:
        pipe = prepared_snapshot_pipe(tmp_path / f"missing-{filename}", seed=71)
        dataset_id = str(pipe.list_datasets("synthetic")["datasets"][0]["dataset_id"])
        missing = tmp_path / f"missing-{filename}" / "data" / "datasets" / dataset_id / filename
        missing.unlink()
        with pytest.raises(SnapshotVerificationError):
            pipe.verify_dataset(dataset_id)


def test_partial_snapshot_create_is_not_registered(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    pipe = DemoPipeline(settings(tmp_path))
    pipe.initialize()
    pipe.generate_demo_data(seed=66)
    pipe.materialize_features("synthetic")

    def broken_write_table(*args: object, **kwargs: object) -> None:
        raise RuntimeError("boom")

    monkeypatch.setattr(snapshot_module.pq, "write_table", broken_write_table)
    with pytest.raises(RuntimeError):
        pipe.create_dataset("synthetic")
    assert pipe.list_datasets("synthetic")["datasets"] == []
    assert list((tmp_path / "data" / "datasets").glob(".tmp-*")) == []


def test_detection_uses_model_dataset_snapshot_not_mutated_sqlite_windows(tmp_path: Path) -> None:
    pipe = DemoPipeline(settings(tmp_path))
    pipe.initialize()
    pipe.generate_demo_data(seed=67)
    pipe.materialize_features("synthetic")
    trained = pipe.train(seed=67)
    detected_before = pipe.detect()
    original_windows = detected_before["windows"]

    pipe.storage.insert_events(
        [
            event(
                999,
                EventType.SYSTEM_METRICS,
                {"cpu_percent": 99.0, "ram_percent": 99.0},
                ts=datetime(2026, 1, 5, tzinfo=UTC),
            )
        ]
    )
    pipe.materialize_features("synthetic")
    detected_after = pipe.detect()

    assert trained["dataset_id"] == model_info(pipe.model_dir("synthetic"))["dataset_id"]
    assert detected_after["windows"] == original_windows
    assert detected_after["evaluation_windows"] == detected_before["evaluation_windows"]


def test_unregistered_public_snapshot_is_rejected_by_verify_load_and_detection(
    tmp_path: Path,
) -> None:
    pipe = DemoPipeline(settings(tmp_path))
    pipe.initialize()
    pipe.generate_demo_data(seed=72)
    pipe.materialize_features("synthetic")
    trained = pipe.train(seed=72)
    dataset_id = str(trained["dataset_id"])
    assert pipe.detect()["windows"] > 0

    with pipe.storage.connect() as conn:
        conn.execute("DELETE FROM dataset_snapshots WHERE dataset_id = ?", (dataset_id,))

    with pytest.raises(SnapshotVerificationError, match="dataset snapshot is not registered"):
        pipe.verify_dataset(dataset_id)
    with pytest.raises(SnapshotVerificationError, match="dataset snapshot is not registered"):
        pipe.snapshots().load_matrix(dataset_id)
    with pytest.raises(SnapshotVerificationError, match="dataset snapshot is not registered"):
        pipe.detect()

    retrained = pipe.train(seed=73)
    assert retrained["dataset_id"] != dataset_id
    assert pipe.storage.get_dataset_snapshot(str(retrained["dataset_id"])) is not None


def test_damaged_manifest_is_rejected(tmp_path: Path) -> None:
    pipe = DemoPipeline(settings(tmp_path))
    pipe.initialize()
    pipe.generate_demo_data(seed=6)
    created = pipe.create_dataset("synthetic")
    dataset_id = str(created["dataset_id"])
    manifest_path = tmp_path / "data" / "datasets" / dataset_id / "manifest.json"
    manifest_path.write_text("{not-json")
    with pytest.raises(SnapshotVerificationError):
        pipe.show_dataset(dataset_id)


def test_dataset_profile_isolation(tmp_path: Path) -> None:
    store = SQLiteStorage(tmp_path / "profile.sqlite3")
    store.initialize()
    start = datetime(2026, 1, 1, tzinfo=UTC)
    store.insert_events(real_profile_events(start, windows=2, synthetic=True, user="u1"))
    store.insert_events(real_profile_events(start, windows=2, synthetic=True, user="u2"))
    FeatureMaterializer(store).materialize("synthetic", rebuild=True)
    pipe = DemoPipeline(settings(tmp_path))
    pipe.storage = store
    with pytest.raises(ValueError):
        pipe.create_dataset("synthetic")


def test_24_usable_coverage_eligibility_and_quality_rejection(tmp_path: Path) -> None:
    store = SQLiteStorage(tmp_path / "eligible.sqlite3")
    store.initialize()
    start = datetime(2026, 1, 1, tzinfo=UTC)
    add_session(store, start, start + timedelta(hours=24))
    add_observations(store, start, windows=96)
    store.insert_events(
        real_profile_events(start, windows=96, synthetic=False)
    )
    FeatureMaterializer(store).materialize("real", rebuild=True)
    pipe = DemoPipeline(settings(tmp_path))
    pipe.storage = store
    eligible = pipe.training_eligibility("real")
    assert eligible["eligible"] is True
    assert eligible["usable_coverage_hours"] == 24

    poor = SQLiteStorage(tmp_path / "poor.sqlite3")
    poor.initialize()
    add_session(poor, start, start + timedelta(hours=24))
    poor.insert_events([event(1, EventType.PROCESS, {"process_name": "a.exe"}, synthetic=False)])
    FeatureMaterializer(poor).materialize("real", rebuild=True)
    poor_pipe = DemoPipeline(settings(tmp_path / "poor"))
    poor_pipe.storage = poor
    assert poor_pipe.training_eligibility("real")["eligible"] is False


def test_stable_host_zero_change_polls_create_good_windows(tmp_path: Path) -> None:
    store = SQLiteStorage(tmp_path / "stable.sqlite3")
    store.initialize()
    start = datetime(2026, 1, 1, tzinfo=UTC)
    add_session(store, start, start + timedelta(minutes=15))
    add_observations(store, start, windows=1)
    store.insert_events(
        [
            event(
                1,
                EventType.SYSTEM_METRICS,
                {"cpu_percent": 5.0, "ram_percent": 35.0},
                ts=start,
                synthetic=False,
            )
        ]
    )
    FeatureMaterializer(store).materialize("real", rebuild=True)
    window = store.list_feature_windows(dataset_kind="real")[0]
    assert window["quality_status"] == "good"
    assert window["features"]["process_count"] == 0
    assert window["features"]["network_connection_count"] == 0


def test_system_metrics_failed_poll_cannot_create_good_window(tmp_path: Path) -> None:
    store = SQLiteStorage(tmp_path / "failed-system-window.sqlite3")
    store.initialize()
    start = datetime(2026, 1, 1, tzinfo=UTC)
    add_session(store, start, start + timedelta(minutes=15))
    add_observations(
        store,
        start,
        windows=1,
        failed_collectors={"windows.system_metrics.psutil"},
    )
    store.insert_events(
        [
            event(
                1,
                EventType.SYSTEM_METRICS,
                {"cpu_percent": 5.0, "ram_percent": 35.0},
                ts=start,
                synthetic=False,
            )
        ]
    )
    FeatureMaterializer(store).materialize("real", rebuild=True)
    window = store.list_feature_windows(dataset_kind="real")[0]
    assert window["quality_status"] != "good"
    assert window["collector_coverage"]["collector_coverage"].get(
        "windows.system_metrics.psutil",
        0,
    ) == 0


def test_failed_system_polls_for_24h_do_not_allow_real_eligibility(tmp_path: Path) -> None:
    store = SQLiteStorage(tmp_path / "failed-system-24h.sqlite3")
    store.initialize()
    start = datetime(2026, 1, 1, tzinfo=UTC)
    add_session(store, start, start + timedelta(hours=24))
    add_observations(
        store,
        start,
        windows=96,
        failed_collectors={"windows.system_metrics.psutil"},
    )
    store.insert_events(real_profile_events(start, windows=96, synthetic=False))
    FeatureMaterializer(store).materialize("real", rebuild=True)
    pipe = DemoPipeline(settings(tmp_path))
    pipe.storage = store
    eligibility = pipe.training_eligibility("real")
    assert eligibility["eligible"] is False
    assert eligibility["avg_system_metrics_coverage"] == 0


def test_heartbeat_gap_reduces_usable_coverage(tmp_path: Path) -> None:
    store = SQLiteStorage(tmp_path / "gap.sqlite3")
    store.initialize()
    start = datetime(2026, 1, 1, tzinfo=UTC)
    add_session(store, start, start + timedelta(hours=24))
    add_observations(store, start, windows=96, gap_start=20, gap_windows=8)
    store.insert_events(real_profile_events(start, windows=96, synthetic=False))
    FeatureMaterializer(store).materialize("real", rebuild=True)
    pipe = DemoPipeline(settings(tmp_path))
    pipe.storage = store
    eligibility = pipe.training_eligibility("real")
    assert eligibility["eligible"] is False
    assert eligibility["usable_coverage_hours"] == 22
    assert eligibility["cumulative_collected_seconds"] >= 24 * 60 * 60


def test_retention_dry_run_and_apply(tmp_path: Path) -> None:
    store = SQLiteStorage(tmp_path / "retention.sqlite3")
    store.initialize()
    old = datetime.now(UTC) - timedelta(days=40)
    store.insert_events(
        [event(1, EventType.PROCESS, {"process_name": "old.exe"}, ts=old, synthetic=False)]
    )
    pipe = DemoPipeline(settings(tmp_path))
    pipe.storage = store
    preview = pipe.retention_preview()
    assert preview["raw_real_events"]["count"] == 1
    applied = pipe.retention_apply()
    assert applied["deleted_raw_real_events"] == 1


def test_stage2_api_and_cli_smoke(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("SENTINELUEBA_DATA_DIR", str(tmp_path / "data"))
    monkeypatch.setenv("SENTINELUEBA_DATABASE_PATH", str(tmp_path / "data" / "api.sqlite3"))
    monkeypatch.setenv("SENTINELUEBA_MODEL_DIR", str(tmp_path / "model"))
    client = TestClient(app)
    assert client.post("/demo/generate", json={"seed": 9}).status_code == 200
    assert (
        client.post("/features/materialize", json={"dataset_kind": "synthetic"}).status_code
        == 200
    )
    dataset = client.post("/datasets", json={"dataset_kind": "synthetic"}).json()["data"]
    assert client.post(f"/datasets/{dataset['dataset_id']}/verify").status_code == 200
    assert client.get("/data-quality").status_code == 200
    assert client.get("/retention/preview").status_code == 200
    assert client.get("/quarantine/summary").status_code == 200

    runner = CliRunner()
    result = runner.invoke(cli_app, ["features", "status"])
    assert result.exit_code == 0


def add_session(store: SQLiteStorage, start: datetime, stop: datetime) -> None:
    with store.connect() as conn:
        conn.execute(
            """
            INSERT INTO collection_sessions (
                session_id, started_at, stopped_at, status, collection_mode,
                enabled_collectors_json, counters_json, errors_json, application_version,
                last_heartbeat_at, last_successful_collection_at
            ) VALUES (?, ?, ?, 'completed', 'real', ?, '{}', '[]', 'test', ?, ?)
            """,
            (
                deterministic_event_id([start.isoformat(), stop.isoformat(), "session"]),
                start.isoformat(),
                stop.isoformat(),
                json.dumps(["collector.process", "collector.system_metrics"]),
                stop.isoformat(),
                stop.isoformat(),
            ),
        )


def prepared_snapshot_pipe(tmp_path: Path, *, seed: int) -> DemoPipeline:
    pipe = DemoPipeline(settings(tmp_path))
    pipe.initialize()
    pipe.generate_demo_data(seed=seed)
    pipe.materialize_features("synthetic")
    pipe.create_dataset("synthetic")
    return pipe


def rewrite_snapshot_with_consistent_hashes(
    pipe: DemoPipeline,
    dataset_id: str,
    rows: list[dict[str, object]],
) -> None:
    dataset_dir = pipe.settings.data_dir / "datasets" / dataset_id
    parquet_path = dataset_dir / "features.parquet"
    manifest_path = dataset_dir / "manifest.json"
    pq.write_table(pa.Table.from_pylist(rows), parquet_path)
    manifest = json.loads(manifest_path.read_text())
    parquet_sha = snapshot_module.sha256_file(parquet_path)
    manifest["parquet_sha256"] = parquet_sha
    manifest_path.write_text(json.dumps(manifest, indent=2, sort_keys=True))
    manifest_sha = snapshot_module.sha256_file(manifest_path)
    (dataset_dir / "checksums.sha256").write_text(
        f"{parquet_sha}  features.parquet\n{manifest_sha}  manifest.json\n"
    )
    with pipe.storage.connect() as conn:
        conn.execute(
            """
            UPDATE dataset_snapshots
            SET manifest_json = ?, manifest_sha256 = ?, parquet_sha256 = ?
            WHERE dataset_id = ?
            """,
            (json.dumps(manifest, sort_keys=True), manifest_sha, parquet_sha, dataset_id),
        )


def create_historical_database(db: Path, version: int) -> None:
    conn = sqlite3.connect(db)
    conn.execute(
        "CREATE TABLE schema_version(version INTEGER PRIMARY KEY, applied_at TEXT NOT NULL)"
    )
    for item in range(1, version + 1):
        conn.execute(
            "INSERT INTO schema_version VALUES (?, '2026-01-01T00:00:00+00:00')",
            (item,),
        )
    conn.execute(
        """
        CREATE TABLE telemetry_events (
            event_id TEXT PRIMARY KEY, timestamp TEXT NOT NULL, event_type TEXT NOT NULL,
            user_id TEXT NOT NULL, host_id TEXT NOT NULL, source TEXT NOT NULL,
            payload_json TEXT NOT NULL, synthetic INTEGER NOT NULL, schema_version TEXT NOT NULL
        )
        """
    )
    conn.execute(
        """
        CREATE TABLE anomalies (
            id INTEGER PRIMARY KEY AUTOINCREMENT, timestamp TEXT NOT NULL, user_id TEXT NOT NULL,
            host_id TEXT NOT NULL, anomaly_score REAL NOT NULL, threshold_value REAL NOT NULL,
            risk_level TEXT NOT NULL, top_features_json TEXT NOT NULL, explanation TEXT NOT NULL,
            model_version TEXT NOT NULL, window_start TEXT NOT NULL, window_end TEXT NOT NULL
        )
        """
    )
    if version >= 2:
        conn.execute(
            "ALTER TABLE anomalies ADD COLUMN feature_contributions_json "
            "TEXT NOT NULL DEFAULT '[]'"
        )
        conn.execute(
            "ALTER TABLE anomalies ADD COLUMN range_kind TEXT NOT NULL DEFAULT 'evaluation'"
        )
        conn.execute(
            """
            CREATE TABLE collection_sessions (
                session_id TEXT PRIMARY KEY, started_at TEXT NOT NULL, stopped_at TEXT,
                status TEXT NOT NULL, collection_mode TEXT NOT NULL,
                enabled_collectors_json TEXT NOT NULL, counters_json TEXT NOT NULL,
                errors_json TEXT NOT NULL, application_version TEXT NOT NULL
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE collector_state (
                collector_id TEXT PRIMARY KEY, status TEXT NOT NULL, cursor_json TEXT NOT NULL,
                last_error TEXT, updated_at TEXT NOT NULL
            )
            """
        )
    if version >= 3:
        conn.execute("ALTER TABLE collection_sessions ADD COLUMN last_heartbeat_at TEXT")
        conn.execute(
            "ALTER TABLE collection_sessions ADD COLUMN last_successful_collection_at TEXT"
        )
    if version >= 4:
        for column, column_type in {
            "ingested_at": "TEXT",
            "collection_session_id": "TEXT",
            "collector_id": "TEXT",
            "collector_version": "TEXT",
            "validation_status": "TEXT",
            "payload_hash": "TEXT",
            "event_schema_version": "TEXT",
        }.items():
            conn.execute(f"ALTER TABLE telemetry_events ADD COLUMN {column} {column_type}")
        conn.execute(
            """
            CREATE TABLE quarantined_events (
                quarantine_id INTEGER PRIMARY KEY AUTOINCREMENT, received_at TEXT NOT NULL,
                collector_id TEXT NOT NULL, source TEXT NOT NULL, event_type TEXT NOT NULL,
                event_schema_version TEXT NOT NULL, error_class TEXT NOT NULL,
                reason TEXT NOT NULL, safe_event_json TEXT NOT NULL, payload_hash TEXT NOT NULL
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE feature_windows (
                window_id TEXT PRIMARY KEY, dataset_kind TEXT NOT NULL, user_id TEXT NOT NULL,
                host_id TEXT NOT NULL, window_start TEXT NOT NULL, window_end TEXT NOT NULL,
                feature_schema_version TEXT NOT NULL, window_size_minutes INTEGER NOT NULL,
                features_json TEXT NOT NULL, event_count INTEGER NOT NULL,
                event_counts_json TEXT NOT NULL, collector_coverage_json TEXT NOT NULL,
                quality_status TEXT NOT NULL, quality_reasons_json TEXT NOT NULL,
                gap_duration_seconds REAL NOT NULL, finalized INTEGER NOT NULL,
                source_event_hash TEXT NOT NULL, created_at TEXT NOT NULL, updated_at TEXT NOT NULL
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE feature_materialization_state (
                dataset_kind TEXT PRIMARY KEY, watermark TEXT, last_materialized_at TEXT NOT NULL,
                late_event_interval_minutes INTEGER NOT NULL, window_size_minutes INTEGER NOT NULL,
                baseline_state_json TEXT NOT NULL, last_rebuild_at TEXT
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE data_quality_runs (
                run_id TEXT PRIMARY KEY, dataset_kind TEXT NOT NULL, created_at TEXT NOT NULL,
                summary_json TEXT NOT NULL
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE dataset_snapshots (
                dataset_id TEXT PRIMARY KEY, dataset_kind TEXT NOT NULL, created_at TEXT NOT NULL,
                manifest_json TEXT NOT NULL, manifest_sha256 TEXT NOT NULL,
                parquet_sha256 TEXT NOT NULL, feature_schema_version TEXT NOT NULL,
                profile_json TEXT NOT NULL, start_at TEXT NOT NULL, end_at TEXT NOT NULL,
                window_count INTEGER NOT NULL, status TEXT NOT NULL
            )
            """
        )
    if version >= 5:
        for column, column_type in {
            "last_ingested_at": "TEXT",
            "last_event_id": "TEXT",
            "event_time_watermark": "TEXT",
            "last_observation_at": "TEXT",
            "last_successful_run_at": "TEXT",
            "late_events_within_policy": "INTEGER NOT NULL DEFAULT 0",
            "late_events_outside_policy": "INTEGER NOT NULL DEFAULT 0",
        }.items():
            conn.execute(
                f"ALTER TABLE feature_materialization_state ADD COLUMN {column} {column_type}"
            )
        conn.execute(
            """
            CREATE TABLE collector_observations (
                observation_id INTEGER PRIMARY KEY AUTOINCREMENT,
                session_id TEXT,
                collector_id TEXT NOT NULL,
                user_id TEXT,
                host_id TEXT,
                observed_at TEXT NOT NULL,
                status TEXT NOT NULL,
                successful_poll INTEGER NOT NULL,
                error_class TEXT,
                configured_interval_seconds REAL NOT NULL,
                returned_events INTEGER NOT NULL,
                saved_events INTEGER NOT NULL
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE late_event_records (
                late_event_id INTEGER PRIMARY KEY AUTOINCREMENT,
                dataset_kind TEXT NOT NULL,
                event_id TEXT NOT NULL,
                event_timestamp TEXT NOT NULL,
                ingested_at TEXT NOT NULL,
                policy_boundary TEXT NOT NULL,
                within_policy INTEGER NOT NULL,
                recorded_at TEXT NOT NULL,
                UNIQUE(dataset_kind, event_id)
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE duplicate_event_records (
                duplicate_id INTEGER PRIMARY KEY AUTOINCREMENT,
                event_id TEXT NOT NULL,
                dataset_kind TEXT NOT NULL,
                first_seen_at TEXT,
                duplicate_seen_at TEXT NOT NULL,
                collector_id TEXT,
                source TEXT NOT NULL
            )
            """
        )
        conn.execute(
            "CREATE INDEX idx_observations_kind_time "
            "ON collector_observations(observed_at, collector_id)"
        )
        conn.execute(
            "CREATE INDEX idx_observations_session "
            "ON collector_observations(session_id)"
        )
        conn.execute(
            "CREATE INDEX idx_late_events_kind_time "
            "ON late_event_records(dataset_kind, event_timestamp)"
        )
        conn.execute(
            "CREATE INDEX idx_duplicate_events_kind "
            "ON duplicate_event_records(dataset_kind, duplicate_seen_at)"
        )
    insert_historical_event(conn, version)
    conn.commit()
    conn.close()


def insert_historical_event(conn: sqlite3.Connection, version: int) -> None:
    values: list[object] = [
        "e1",
        "2026-01-01T00:00:00+00:00",
        "system_metrics",
        "u",
        "h",
        "test",
        json.dumps({"cpu_percent": 10.0, "ram_percent": 40.0}),
        1,
        "event-v1",
    ]
    columns = [
        "event_id",
        "timestamp",
        "event_type",
        "user_id",
        "host_id",
        "source",
        "payload_json",
        "synthetic",
        "schema_version",
    ]
    if version >= 4:
        columns.extend(
            [
                "ingested_at",
                "collection_session_id",
                "collector_id",
                "collector_version",
                "validation_status",
                "payload_hash",
                "event_schema_version",
            ]
        )
        values.extend(
            [
                "2026-01-01T00:00:01+00:00",
                None,
                "test",
                "unknown",
                "accepted",
                "historical-hash",
                "event-v1",
            ]
        )
    conn.execute(
        f"INSERT INTO telemetry_events ({', '.join(columns)}) "
        f"VALUES ({', '.join('?' for _ in columns)})",
        values,
    )


def table_names(db: Path) -> set[str]:
    with sqlite3.connect(db) as conn:
        return {
            row[0]
            for row in conn.execute("SELECT name FROM sqlite_master WHERE type = 'table'")
        }


class InstrumentedStorage(SQLiteStorage):
    def __init__(self, database_path: Path) -> None:
        super().__init__(database_path)
        self.reset_instrumentation()

    def reset_instrumentation(self) -> None:
        self.event_row_calls: list[dict[str, object]] = []
        self.observation_calls: list[dict[str, object]] = []
        self.event_rows_read: list[int] = []
        self.observation_rows_read: list[int] = []
        self.unrestricted_event_reads = 0
        self.unrestricted_observation_reads = 0

    def list_event_rows(self, **kwargs: object) -> list[dict[str, object]]:
        self.event_row_calls.append(dict(kwargs))
        if not any(
            kwargs.get(key) is not None
            for key in ["since", "ingested_after", "after_event_id", "start", "end"]
        ):
            self.unrestricted_event_reads += 1
        rows = super().list_event_rows(**kwargs)  # type: ignore[arg-type]
        self.event_rows_read.append(len(rows))
        return rows

    def list_collector_observations(self, **kwargs: object) -> list[dict[str, object]]:
        self.observation_calls.append(dict(kwargs))
        if not any(
            kwargs.get(key) is not None
            for key in ["since", "after_observation_id", "start", "end"]
        ):
            self.unrestricted_observation_reads += 1
        rows = super().list_collector_observations(**kwargs)  # type: ignore[arg-type]
        self.observation_rows_read.append(len(rows))
        return rows

    def list_collector_observations_overlapping(
        self,
        **kwargs: object,
    ) -> list[dict[str, object]]:
        self.observation_calls.append({"overlapping": True, **dict(kwargs)})
        rows = super().list_collector_observations_overlapping(**kwargs)  # type: ignore[arg-type]
        self.observation_rows_read.append(len(rows))
        return rows


def add_observations(
    store: SQLiteStorage,
    start: datetime,
    *,
    windows: int,
    interval_seconds: int = 15 * 60,
    gap_start: int | None = None,
    gap_windows: int = 0,
    failed_collectors: set[str] | None = None,
) -> None:
    failed = failed_collectors or set()
    for index in range(windows):
        if gap_start is not None and gap_start <= index < gap_start + gap_windows:
            continue
        observed_at = start + timedelta(minutes=15 * index)
        for collector_id in [
            "windows.system_metrics.psutil",
            "windows.process.psutil",
            "windows.network.psutil",
        ]:
            successful = collector_id not in failed
            store.record_collector_observation(
                session_id="fixture-session",
                collector_id=collector_id,
                user_id="user-a",
                host_id="host-a",
                observed_at=observed_at,
                status="ok" if successful else "error",
                successful_poll=successful,
                error_class=None if successful else "FixturePollError",
                configured_interval_seconds=interval_seconds,
                returned_events=0,
                saved_events=0,
            )


def real_profile_events(
    start: datetime,
    *,
    windows: int,
    synthetic: bool,
    user: str = "user-a",
    host: str = "host-a",
    include_network: bool = False,
) -> list[TelemetryEvent]:
    events: list[TelemetryEvent] = []
    for index in range(windows):
        ts = start + timedelta(minutes=15 * index)
        events.append(
            event(
                index * 2,
                EventType.PROCESS,
                {"process_name": "editor.exe"},
                ts=ts,
                synthetic=synthetic,
                user=user,
                host=host,
            )
        )
        events.append(
            event(
                index * 2 + 1,
                EventType.SYSTEM_METRICS,
                {"cpu_percent": 10.0, "ram_percent": 40.0},
                ts=ts,
                synthetic=synthetic,
                user=user,
                host=host,
            )
        )
        if include_network:
            events.append(
                event(
                    index * 3 + 10_000,
                    EventType.NETWORK,
                    {"remote_address": "198.51.100.20", "remote_port": 443},
                    ts=ts,
                    synthetic=synthetic,
                    user=user,
                    host=host,
                )
            )
    return events


def comparable_feature_windows(windows: list[dict[str, object]]) -> list[dict[str, object]]:
    comparable: list[dict[str, object]] = []
    for window in windows:
        copy = dict(window)
        copy.pop("created_at", None)
        copy.pop("updated_at", None)
        comparable.append(copy)
    return sorted(comparable, key=lambda item: str(item["window_start"]))


def event(
    index: int,
    event_type: EventType,
    payload: dict[str, object],
    *,
    ts: datetime | None = None,
    synthetic: bool = True,
    user: str = "user-a",
    host: str = "host-a",
) -> TelemetryEvent:
    timestamp = ts or datetime(2026, 1, 1, 10, 0, tzinfo=UTC) + timedelta(seconds=index)
    return TelemetryEvent(
        event_id=deterministic_event_id(
            [str(index), timestamp.isoformat(), event_type.value, user, host, str(synthetic)]
        ),
        timestamp=timestamp,
        event_type=event_type,
        user_id=user,
        host_id=host,
        source="test-collector",
        payload=payload,
        synthetic=synthetic,
    )
