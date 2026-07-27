from __future__ import annotations

import sqlite3
import sys
import time
from datetime import UTC, datetime
from pathlib import Path
from types import SimpleNamespace

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
from sentinelueba.collectors.manager import (
    CollectionAlreadyRunningError,
    CollectorManager,
    NoAvailableCollectorsError,
)
from sentinelueba.collectors.network import NetworkSnapshot, diff_network_snapshots
from sentinelueba.collectors.process import ProcessSnapshot, diff_process_snapshots
from sentinelueba.collectors.system_metrics import SystemMetricsCollector
from sentinelueba.collectors.windows_auth import WindowsAuthCollector, parse_auth_fixture
from sentinelueba.config import Settings
from sentinelueba.detection.engine import detect_anomalies
from sentinelueba.domain.events import EventType, TelemetryEvent, deterministic_event_id
from sentinelueba.features.windows import build_feature_windows, windows_to_matrix
from sentinelueba.ml.autoencoder import load_model, train_autoencoder
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
    previous = {1: ProcessSnapshot(1, 10.0, "a.exe", None, None, None)}
    current = {2: ProcessSnapshot(2, 20.0, "b.exe", None, 1, "a.exe")}
    assert diff_process_snapshots(previous, current) == [
        ("started", current[2]),
        ("stopped", previous[1]),
    ]


def test_process_snapshot_diff_handles_pid_reuse() -> None:
    previous = {10: ProcessSnapshot(10, 100.0, "old.exe", None, None, None)}
    current = {10: ProcessSnapshot(10, 200.0, "new.exe", None, None, None)}
    assert diff_process_snapshots(previous, current) == [
        ("stopped", previous[10]),
        ("started", current[10]),
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
    assert "logon_type" in first.payload


def test_windows_auth_parser_filters_accounts_and_logon_types() -> None:
    base = {"EventID": 4624, "RecordID": 1, "LogonType": 2, "TargetUserName": "analyst"}
    assert parse_auth_fixture(base) is not None
    assert parse_auth_fixture(base | {"LogonType": 3}) is None
    assert parse_auth_fixture(base | {"TargetUserName": "SYSTEM"}) is None
    assert parse_auth_fixture(base | {"TargetUserName": "HOST$"}) is None


def test_windows_auth_evt_query_cursor_and_handles(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fake_evt = FakeEvtModule(
        [
            auth_xml(100, 4624, "existing", 2),
            auth_xml(101, 4624, "analyst", 2),
            auth_xml(102, 4624, "service", 3),
        ]
    )
    monkeypatch.setattr("platform.system", lambda: "Windows")
    monkeypatch.setitem(sys.modules, "win32evtlog", fake_evt)
    collector = WindowsAuthCollector("u", "h")
    collector.start()
    assert collector.cursor["last_record_id"] == 102
    fake_evt.records.append(auth_xml(103, 4625, "analyst", 2, status="0xC000006D"))
    events = collector.collect()
    assert [event.payload["record_id"] for event in events] == [103]
    assert collector.cursor["last_record_id"] == 103
    assert fake_evt.closed


def test_windows_auth_evt_query_uses_pywin32_argument_order(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fake_evt = FakeEvtModule([auth_xml(100, 4624, "existing", 2)])
    monkeypatch.setattr("platform.system", lambda: "Windows")
    monkeypatch.setitem(sys.modules, "win32evtlog", fake_evt)
    collector = WindowsAuthCollector("u", "h")

    capability = collector.check_availability()
    assert capability.status == CollectorStatus.AVAILABLE
    availability_call = fake_evt.query_calls[-1]
    assert availability_call["path"] == "Security"
    assert availability_call["flags"] == fake_evt.EvtQueryChannelPath
    assert isinstance(availability_call["flags"], int)
    assert isinstance(availability_call["query"], str)

    collector.start()
    latest_call = fake_evt.query_calls[-1]
    assert latest_call["flags"] == (
        fake_evt.EvtQueryChannelPath | fake_evt.EvtQueryReverseDirection
    )
    assert isinstance(latest_call["flags"], int)
    assert isinstance(latest_call["query"], str)

    fake_evt.records.append(auth_xml(101, 4625, "analyst", 2, status="0xC000006D"))
    events = collector.collect()
    assert [event.payload["record_id"] for event in events] == [101]
    live_call = fake_evt.query_calls[-1]
    assert live_call["flags"] == fake_evt.EvtQueryChannelPath
    assert not int(live_call["flags"]) & fake_evt.EvtQueryReverseDirection
    assert isinstance(live_call["flags"], int)
    assert isinstance(live_call["query"], str)

    with pytest.raises(TypeError):
        fake_evt.EvtQuery(
            "Security",
            "bad-query-in-flags-position",  # type: ignore[arg-type]
            fake_evt.EvtQueryChannelPath,  # type: ignore[arg-type]
        )


def test_windows_auth_permission_required(monkeypatch: pytest.MonkeyPatch) -> None:
    fake_evt = FakeEvtModule([], permission_error=True)
    monkeypatch.setattr("platform.system", lambda: "Windows")
    monkeypatch.setitem(sys.modules, "win32evtlog", fake_evt)
    capability = WindowsAuthCollector("u", "h").check_availability()
    assert capability.status == CollectorStatus.PERMISSION_REQUIRED


def test_identity_pseudonymization_uses_local_secret(tmp_path: Path) -> None:
    provider = IdentityProvider(tmp_path)
    first = provider.user_host()
    second = IdentityProvider(tmp_path).user_host()
    assert first == second
    assert (tmp_path / "identity.secret").exists()
    assert not first[0].startswith("maksut")


def test_migration_v1_to_current_preserves_events(tmp_path: Path) -> None:
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
    assert store.status()["schema_version"] == 3
    assert store.status()["event_count"] == 1
    assert "collection_sessions" in {
        row[0] for row in sqlite3.connect(db).execute("SELECT name FROM sqlite_master")
    }


def test_migration_v2_to_current_adds_heartbeat(tmp_path: Path) -> None:
    db = tmp_path / "v2.sqlite3"
    store = SQLiteStorage(db)
    store.initialize()
    conn = sqlite3.connect(db)
    conn.execute("DELETE FROM schema_version WHERE version = 3")
    columns = [row[1] for row in conn.execute("PRAGMA table_info(collection_sessions)")]
    if "last_heartbeat_at" in columns:
        conn.execute("ALTER TABLE collection_sessions RENAME TO collection_sessions_old")
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
        conn.execute("DROP TABLE collection_sessions_old")
    conn.commit()
    conn.close()
    store.initialize()
    columns = {
        row[1] for row in sqlite3.connect(db).execute("PRAGMA table_info(collection_sessions)")
    }
    assert "last_heartbeat_at" in columns
    assert store.status()["schema_version"] == 3


def test_downtime_after_heartbeat_is_not_counted(tmp_path: Path) -> None:
    store = SQLiteStorage(tmp_path / "downtime.sqlite3")
    store.initialize()
    conn = sqlite3.connect(store.database_path)
    conn.execute(
        """
        INSERT INTO collection_sessions (
            session_id, started_at, stopped_at, status, collection_mode,
            enabled_collectors_json, counters_json, errors_json, application_version,
            last_heartbeat_at, last_successful_collection_at
        ) VALUES (?, ?, NULL, 'running', 'real', '[]', '{}', '[]', 'test', ?, ?)
        """,
        (
            "s1",
            "2026-01-01T00:00:00+00:00",
            "2026-01-01T00:00:10+00:00",
            "2026-01-01T00:00:10+00:00",
        ),
    )
    conn.commit()
    conn.close()
    store.mark_stale_running_sessions()
    progress = store.collection_progress()
    assert progress["cumulative_collected_seconds"] == 10


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


class UnavailableCollector(FakeCollector):
    collector_id = "fake.unavailable"

    def check_availability(self) -> CollectorCapability:
        return CollectorCapability(
            self.collector_id,
            self.version,
            CollectorStatus.UNAVAILABLE,
            self.required_privilege,
            "fake unavailable",
        )


def test_collector_failure_isolation_and_collection_smoke(tmp_path: Path) -> None:
    manager = CollectorManager(settings(tmp_path))
    manager.build_collectors = lambda enabled=None: [  # type: ignore[method-assign]
        FakeCollector(),
        FakeCollector(fail=True),
    ]
    manager.start(duration_seconds=1, interval_seconds=0.1)
    time.sleep(1.3)
    status = manager.status()
    assert status["running"] is False
    assert status["counters"]["fake.collector"] >= 1
    assert status["errors"]
    assert manager.progress()["cumulative_collected_seconds"] > 0


def test_empty_collection_session_is_rejected(tmp_path: Path) -> None:
    manager = CollectorManager(settings(tmp_path))
    manager.build_collectors = lambda enabled=None: [UnavailableCollector()]  # type: ignore[method-assign]
    with pytest.raises(NoAvailableCollectorsError):
        manager.start(duration_seconds=1)
    assert manager.sessions() == []


def test_concurrent_start_rejection(tmp_path: Path) -> None:
    manager = CollectorManager(settings(tmp_path))
    manager.build_collectors = lambda enabled=None: [FakeCollector()]  # type: ignore[method-assign]
    manager.start(duration_seconds=2, interval_seconds=0.2)
    with pytest.raises(CollectionAlreadyRunningError):
        manager.start(duration_seconds=1)
    manager.stop()


def test_stop_interrupts_large_polling_interval(tmp_path: Path) -> None:
    manager = CollectorManager(settings(tmp_path))
    manager.build_collectors = lambda enabled=None: [FakeCollector()]  # type: ignore[method-assign]
    manager.start(interval_seconds=60)
    time.sleep(0.2)
    start = time.monotonic()
    status = manager.stop()
    elapsed = time.monotonic() - start
    assert elapsed < 2
    assert status["running"] is False
    assert manager.sessions()[0]["status"] == "stopped"
    assert manager.sessions()[0]["stopped_at"] is not None


def test_real_synthetic_dataset_separation(tmp_path: Path) -> None:
    store = SQLiteStorage(tmp_path / "events.sqlite3")
    store.initialize()
    store.insert_events([event(1, synthetic=True), event(2, synthetic=False)])
    assert len(store.list_events(synthetic=True)) == 1
    assert len(store.list_events(synthetic=False)) == 1
    inserted, by_type = store.insert_events_detailed([event(2, synthetic=False)])
    assert inserted == 0
    assert by_type == {}


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


def test_model_sha256_mismatch_is_rejected(tmp_path: Path) -> None:
    normal_events = generate_synthetic_events(seed=42, include_anomalies=False)[0]
    windows = build_feature_windows(normal_events)
    train_autoencoder(windows_to_matrix(windows[:24]), tmp_path / "model", epochs=8)
    model_path = tmp_path / "model" / "autoencoder.pt"
    model_path.write_bytes(model_path.read_bytes() + b"tamper")
    with pytest.raises(ValueError, match="SHA-256 mismatch"):
        load_model(tmp_path / "model")


def test_demo_scenario_manifest_windows_are_all_detected(tmp_path: Path) -> None:
    pipe = DemoPipeline(settings(tmp_path))
    pipe.generate_demo_data(seed=42)
    pipe.train(seed=42)
    detected = pipe.detect()
    validation = detected["scenario_validation"]
    assert len(validation) == 5
    assert {item["scenario_name"] for item in validation} == {
        "rare_process",
        "outbound_connection_spike",
        "atypical_time_activity",
        "cpu_ram_spike",
        "failed_login_series",
    }
    assert all(item["detected"] is True for item in validation)


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


class FakeEvtModule(SimpleNamespace):
    EvtQueryChannelPath = 1
    EvtQueryReverseDirection = 2
    EvtRenderEventXml = 1

    def __init__(self, records: list[str], permission_error: bool = False) -> None:
        super().__init__()
        self.records = records
        self.permission_error = permission_error
        self.closed: list[object] = []
        self.query_calls: list[dict[str, object]] = []

    def EvtQuery(  # noqa: N802 - mirrors pywin32's public API name.
        self,
        Path: str,
        Flags: int,
        Query: str | None = None,
        Session: object | None = None,
    ) -> dict[str, object]:
        if not isinstance(Flags, int):
            raise TypeError("flags must be int")
        if Query is not None and not isinstance(Query, str):
            raise TypeError("query must be str")
        if self.permission_error:
            raise PermissionError("denied")
        call = {"path": Path, "flags": Flags, "query": Query, "session": Session}
        self.query_calls.append(call)
        return {"query": Query or "", "flags": Flags}

    def EvtNext(self, handle: dict[str, object], count: int) -> list[dict[str, object]]:
        last_record_id = int(str(handle["query"]).split("EventRecordID>")[1].split("]")[0])
        records = [
            {"xml": xml, "id": record_id_from_xml(xml)}
            for xml in self.records
            if record_id_from_xml(xml) > last_record_id
        ]
        if int(handle["flags"]) & self.EvtQueryReverseDirection:
            records = list(reversed(records[:]))
        batch = records[:count]
        batch_ids = {record["id"] for record in batch}
        self.records = [
            xml for xml in self.records if record_id_from_xml(xml) not in batch_ids
        ]
        return batch

    def EvtRender(self, handle: dict[str, object], flags: int) -> str:
        return str(handle["xml"])

    def EvtClose(self, handle: object) -> None:
        self.closed.append(handle)


def auth_xml(
    record_id: int,
    event_id: int,
    user: str,
    logon_type: int | None,
    status: str = "",
) -> str:
    logon = "" if logon_type is None else f'<Data Name="LogonType">{logon_type}</Data>'
    return f"""
    <Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
      <System>
        <EventID>{event_id}</EventID>
        <TimeCreated SystemTime="2026-01-01T00:00:00.000000Z" />
        <EventRecordID>{record_id}</EventRecordID>
      </System>
      <EventData>
        <Data Name="TargetUserName">{user}</Data>
        <Data Name="TargetDomainName">DEMO</Data>
        {logon}
        <Data Name="Status">{status}</Data>
      </EventData>
    </Event>
    """


def record_id_from_xml(xml: str) -> int:
    return int(xml.split("<EventRecordID>")[1].split("</EventRecordID>")[0])
