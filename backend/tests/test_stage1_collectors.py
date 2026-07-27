from __future__ import annotations

import sqlite3
import time
from datetime import UTC, datetime
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from sentinelueba.api.main import app
from sentinelueba.collectors.base import (
    CollectorCapability,
    CollectorHealth,
    CollectorStatus,
    PrivilegeLevel,
)
from sentinelueba.collectors.identity import IdentityProvider
from sentinelueba.collectors.manager import CollectionAlreadyRunningError, CollectorManager
from sentinelueba.collectors.network import NetworkSnapshot, diff_network_snapshots
from sentinelueba.collectors.process import ProcessSnapshot, diff_process_snapshots
from sentinelueba.collectors.system_metrics import SystemMetricsCollector
from sentinelueba.collectors.windows_auth import WindowsAuthCollector, parse_auth_fixture
from sentinelueba.config import Settings
from sentinelueba.detection.engine import detect_anomalies
from sentinelueba.domain.events import EventType, TelemetryEvent, deterministic_event_id
from sentinelueba.features.windows import build_feature_windows, windows_to_matrix
from sentinelueba.ml.autoencoder import train_autoencoder
from sentinelueba.services.pipeline import DemoPipeline
from sentinelueba.storage.sqlite import SQLiteStorage
from sentinelueba.telemetry.synthetic import generate_synthetic_events


def settings(tmp_path: Path) -> Settings:
    return Settings(
        data_dir=tmp_path / "data",
        database_path=tmp_path / "data" / "stage1.sqlite3",
        model_dir=tmp_path / "model",
    )


def event(index: int, synthetic: bool = False) -> TelemetryEvent:
    timestamp = datetime(2026, 1, 1, 12, index, tzinfo=UTC)
    return TelemetryEvent(
        event_id=deterministic_event_id(["stage1", str(index), str(synthetic)]),
        timestamp=timestamp,
        event_type=EventType.SYSTEM_METRICS,
        user_id="user-a",
        host_id="host-a",
        source="test",
        payload={"cpu_percent": 10 + index, "ram_percent": 40},
        synthetic=synthetic,
    )


def test_process_snapshot_diff() -> None:
    previous = {1: ProcessSnapshot(1, "a.exe", None, None, None)}
    current = {2: ProcessSnapshot(2, "b.exe", None, 1, "a.exe")}
    assert diff_process_snapshots(previous, current) == [
        ("started", current[2]),
        ("stopped", previous[1]),
    ]


def test_network_snapshot_diff() -> None:
    old = NetworkSnapshot("tcp", "ESTABLISHED", "198.51.100.1", 443, 50000, 10, "app.exe")
    new = NetworkSnapshot("udp", "NONE", "198.51.100.2", 53, 50001, None, None)
    assert diff_network_snapshots({old.key: old}, {new.key: new}) == [
        ("opened", new),
        ("closed", old),
    ]


def test_system_metrics_first_counter_delta(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("platform.system", lambda: "Windows")
    collector = SystemMetricsCollector("u", "h")
    collector.start()
    events = collector.collect()
    assert len(events) == 1
    assert events[0].payload["network_bytes_sent_delta"] >= 0


def test_windows_auth_fixture_parser_and_cursor() -> None:
    collector = WindowsAuthCollector("u", "h", {"last_record_id": 100})
    fixture = {
        "EventID": 4625,
        "RecordID": 101,
        "LogonType": 2,
        "TargetUserName": "analyst",
        "FailureReason": "bad_password",
    }
    parsed = parse_auth_fixture(fixture)
    assert parsed is not None
    assert parsed["result"] == "failure"
    first = collector.event_from_fixture(fixture, datetime.now(UTC))
    duplicate = collector.event_from_fixture(fixture, datetime.now(UTC))
    assert first is not None
    assert duplicate is None


def test_identity_pseudonymization_uses_local_secret(tmp_path: Path) -> None:
    provider = IdentityProvider(tmp_path)
    first = provider.user_host()
    second = IdentityProvider(tmp_path).user_host()
    assert first == second
    assert (tmp_path / "identity.secret").exists()
    assert not first[0].startswith("maksut")


def test_migration_v1_to_v2_preserves_events(tmp_path: Path) -> None:
    db = tmp_path / "v1.sqlite3"
    conn = sqlite3.connect(db)
    conn.execute(
        "CREATE TABLE schema_version(version INTEGER PRIMARY KEY, applied_at TEXT NOT NULL)"
    )
    conn.execute("INSERT INTO schema_version VALUES (1, '2026-01-01T00:00:00+00:00')")
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
    conn.execute(
        "INSERT INTO telemetry_events VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
        (
            "e1",
            "2026-01-01T00:00:00+00:00",
            "system_metrics",
            "u",
            "h",
            "test",
            "{}",
            1,
            "0.1",
        ),
    )
    conn.commit()
    conn.close()
    store = SQLiteStorage(db)
    store.initialize()
    assert store.status()["schema_version"] == 2
    assert store.status()["event_count"] == 1
    assert "collection_sessions" in {
        row[0] for row in sqlite3.connect(db).execute("SELECT name FROM sqlite_master")
    }


class FakeCollector:
    collector_id = "fake.collector"
    version = "1.0"
    required_privilege = PrivilegeLevel.USER

    def __init__(self, fail: bool = False) -> None:
        self.fail = fail
        self.events = 0

    def check_availability(self) -> CollectorCapability:
        return CollectorCapability(
            self.collector_id,
            self.version,
            CollectorStatus.AVAILABLE,
            self.required_privilege,
            "fake",
        )

    def start(self) -> None:
        pass

    def stop(self) -> None:
        pass

    def health(self) -> CollectorHealth:
        return CollectorHealth(
            self.collector_id,
            CollectorStatus.RUNNING,
            events_collected=self.events,
        )

    def collect(self) -> list[TelemetryEvent]:
        if self.fail:
            raise RuntimeError("isolated")
        self.events += 1
        return [event(self.events, synthetic=False)]


def test_collector_failure_isolation_and_collection_smoke(tmp_path: Path) -> None:
    manager = CollectorManager(settings(tmp_path))
    manager.build_collectors = lambda enabled=None: [FakeCollector(), FakeCollector(fail=True)]  # type: ignore[method-assign]
    manager.start(duration_seconds=1, interval_seconds=0.1)
    time.sleep(1.3)
    status = manager.status()
    assert status["running"] is False
    assert status["counters"]["fake.collector"] >= 1
    assert status["errors"]
    assert manager.progress()["cumulative_collected_seconds"] > 0


def test_concurrent_start_rejection(tmp_path: Path) -> None:
    manager = CollectorManager(settings(tmp_path))
    manager.build_collectors = lambda enabled=None: [FakeCollector()]  # type: ignore[method-assign]
    manager.start(duration_seconds=2, interval_seconds=0.2)
    with pytest.raises(CollectionAlreadyRunningError):
        manager.start(duration_seconds=1)
    manager.stop()


def test_real_synthetic_dataset_separation(tmp_path: Path) -> None:
    store = SQLiteStorage(tmp_path / "events.sqlite3")
    store.initialize()
    store.insert_events([event(1, synthetic=True), event(2, synthetic=False)])
    assert len(store.list_events(synthetic=True)) == 1
    assert len(store.list_events(synthetic=False)) == 1


def test_per_feature_reconstruction_contributions(tmp_path: Path) -> None:
    normal_events = generate_synthetic_events(seed=41, include_anomalies=False)[0]
    windows = build_feature_windows(normal_events)
    model, preprocessor, _ = train_autoencoder(
        windows_to_matrix(windows[:24]),
        tmp_path / "model",
        epochs=8,
    )
    anomalous = windows[25].model_copy(
        update={"features": windows[25].features | {"network_connection_count": 200.0}}
    )
    anomalies = detect_anomalies(model, preprocessor, [anomalous])
    assert anomalies
    contribution = anomalies[0].feature_contributions[0]
    assert {
        "feature_name",
        "observed_value",
        "expected_value",
        "contribution",
        "direction",
    } <= set(contribution)


def test_demo_scenario_manifest_windows_are_detected_or_reported(tmp_path: Path) -> None:
    pipe = DemoPipeline(settings(tmp_path))
    generated = pipe.generate_demo_data(seed=42)
    pipe.train(seed=42)
    detected = pipe.detect()
    detected_windows = {item["window_start"] for item in detected["top_anomalies"]}
    manifest = generated["scenario_manifest"]
    assert len(manifest) == 5
    missed = [
        item["name"]
        for item in manifest
        if item["window_start"].replace("+00:00", "Z") not in detected_windows
    ]
    assert len(missed) < 5


def test_api_stage1_endpoints(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("SENTINELUEBA_DATA_DIR", str(tmp_path / "data"))
    monkeypatch.setenv("SENTINELUEBA_DATABASE_PATH", str(tmp_path / "data" / "api.sqlite3"))
    monkeypatch.setenv("SENTINELUEBA_MODEL_DIR", str(tmp_path / "model"))
    client = TestClient(app)
    assert client.get("/collectors/capabilities").status_code == 200
    assert client.get("/collectors/status").status_code == 200
    assert client.get("/collection/progress").status_code == 200
    assert client.get("/events/summary").status_code == 200
    eligibility = client.post("/training/eligibility", json={"dataset_kind": "real"}).json()["data"]
    assert eligibility["eligible"] is False
    assert "24 cumulative hours" in eligibility["reason"]
