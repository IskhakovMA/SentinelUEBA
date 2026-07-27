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
from sentinelueba.storage.sqlite import SQLiteStorage
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
            "EventID": 4624,
            "RecordID": 101,
            "LogonType": 2,
            "TargetUserName": "analyst",
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


def test_event_metadata_migration_v3_to_latest(tmp_path: Path) -> None:
    db = tmp_path / "v3.sqlite3"
    store = SQLiteStorage(db)
    store.initialize()
    conn = sqlite3.connect(db)
    conn.execute("DELETE FROM schema_version WHERE version = 4")
    conn.execute("DROP TABLE IF EXISTS dataset_snapshots")
    conn.commit()
    conn.close()
    store.initialize()
    assert store.status()["schema_version"] == 5
    columns = {
        row[1] for row in sqlite3.connect(db).execute("PRAGMA table_info(telemetry_events)")
    }
    assert {"ingested_at", "collection_session_id", "payload_hash"}.issubset(columns)


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


def add_observations(
    store: SQLiteStorage,
    start: datetime,
    *,
    windows: int,
    gap_start: int | None = None,
    gap_windows: int = 0,
) -> None:
    for index in range(windows):
        if gap_start is not None and gap_start <= index < gap_start + gap_windows:
            continue
        observed_at = start + timedelta(minutes=15 * index)
        for collector_id in [
            "windows.system_metrics.psutil",
            "windows.process.psutil",
            "windows.network.psutil",
        ]:
            store.record_collector_observation(
                session_id="fixture-session",
                collector_id=collector_id,
                user_id="user-a",
                host_id="host-a",
                observed_at=observed_at,
                status="ok",
                successful_poll=True,
                error_class=None,
                configured_interval_seconds=15 * 60,
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
