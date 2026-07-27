from __future__ import annotations

import json
import sqlite3
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from typer.testing import CliRunner

from sentinelueba.api.main import app
from sentinelueba.cli import app as cli_app
from sentinelueba.config import Settings
from sentinelueba.datasets import SnapshotVerificationError
from sentinelueba.domain.events import EventType, TelemetryEvent, deterministic_event_id
from sentinelueba.features.materialization import FeatureMaterializer
from sentinelueba.features.windows import align_window_start
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
    assert store.status()["schema_version"] == 4
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
    assert first["upserted_windows"] == second["upserted_windows"]
    assert store.feature_window_summary()["synthetic"]["good"] == 2
    assert store.feature_window_summary()["real"]["insufficient"] == 2


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
    matrix, manifest = pipe.snapshots().load_matrix(dataset_id)
    assert matrix
    assert manifest["dataset_id"] == dataset_id
    parquet_path = tmp_path / "data" / "datasets" / dataset_id / "features.parquet"
    parquet_path.write_bytes(parquet_path.read_bytes() + b"corruption")
    with pytest.raises(SnapshotVerificationError):
        pipe.verify_dataset(dataset_id)


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
    store.insert_events(
        real_profile_events(start, windows=96, synthetic=False, include_network=True)
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
