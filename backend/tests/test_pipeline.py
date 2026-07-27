from __future__ import annotations

from pathlib import Path

from fastapi.testclient import TestClient

from sentinelueba.api.main import app
from sentinelueba.config import Settings
from sentinelueba.detection.engine import classify_risk
from sentinelueba.domain.events import AnomalyRisk
from sentinelueba.features.windows import FEATURE_NAMES, build_feature_windows, windows_to_matrix
from sentinelueba.ml.autoencoder import load_model, train_autoencoder
from sentinelueba.normalization.normalizer import normalize_event
from sentinelueba.services.pipeline import DemoPipeline
from sentinelueba.storage.sqlite import SQLiteStorage
from sentinelueba.telemetry.synthetic import generate_synthetic_events


def settings(tmp_path: Path) -> Settings:
    return Settings(
        data_dir=tmp_path / "data",
        database_path=tmp_path / "data" / "test.sqlite3",
        model_dir=tmp_path / "model",
    )


def test_synthetic_generator_is_seed_reproducible() -> None:
    first, first_summary = generate_synthetic_events(seed=7)
    second, second_summary = generate_synthetic_events(seed=7)
    assert first_summary.events == second_summary.events
    assert [event.event_id for event in first[:20]] == [event.event_id for event in second[:20]]
    assert len(first_summary.anomaly_scenarios) == 5


def test_normalizer_removes_unknown_payload_keys() -> None:
    event = generate_synthetic_events(seed=1)[0][0].model_copy(
        update={"payload": {"process_name": "x.exe", "unsafe": "drop"}}
    )
    normalized = normalize_event(event)
    assert normalized.payload == {"process_name": "x.exe"}


def test_storage_deduplicates_events(tmp_path: Path) -> None:
    store = SQLiteStorage(tmp_path / "events.sqlite3")
    store.initialize()
    events = generate_synthetic_events(seed=11)[0][:5]
    assert store.insert_events(events) == 5
    assert store.insert_events(events) == 0
    assert store.status()["event_count"] == 5


def test_feature_windows_include_required_features() -> None:
    events = generate_synthetic_events(seed=12)[0]
    windows = build_feature_windows(events)
    assert windows
    assert set(FEATURE_NAMES).issubset(windows[0].features)
    assert len(windows_to_matrix(windows)[0]) == len(FEATURE_NAMES)


def test_model_training_save_load_and_scoring(tmp_path: Path) -> None:
    normal_events = generate_synthetic_events(seed=13, include_anomalies=False)[0]
    windows = build_feature_windows(normal_events)
    matrix = windows_to_matrix(windows[:24])
    model, preprocessor, losses = train_autoencoder(matrix, tmp_path / "model", epochs=8)
    loaded_model, loaded_preprocessor = load_model(tmp_path / "model")
    assert losses[-1] >= 0
    assert preprocessor.threshold > 0
    assert loaded_preprocessor.feature_names == preprocessor.feature_names
    assert loaded_model is not model


def test_risk_classification() -> None:
    assert classify_risk(0.5, 1.0) == AnomalyRisk.NORMAL
    assert classify_risk(1.1, 1.0) == AnomalyRisk.LOW
    assert classify_risk(1.5, 1.0) == AnomalyRisk.MEDIUM
    assert classify_risk(2.0, 1.0) == AnomalyRisk.HIGH
    assert classify_risk(3.0, 1.0) == AnomalyRisk.CRITICAL


def test_e2e_smoke_detects_injected_anomalies(tmp_path: Path) -> None:
    pipe = DemoPipeline(settings(tmp_path))
    pipe.initialize()
    generated = pipe.generate_demo_data(seed=21)
    trained = pipe.train(seed=21)
    detected = pipe.detect()
    assert generated["inserted_events"] > 0
    assert trained["trained"] is True
    assert detected["anomalies"] >= 3
    assert detected["summary"]["max_score"] > trained["threshold"]


def test_api_endpoints(tmp_path: Path, monkeypatch) -> None:  # type: ignore[no-untyped-def]
    monkeypatch.setenv("SENTINELUEBA_DATA_DIR", str(tmp_path / "data"))
    monkeypatch.setenv("SENTINELUEBA_DATABASE_PATH", str(tmp_path / "data" / "api.sqlite3"))
    monkeypatch.setenv("SENTINELUEBA_MODEL_DIR", str(tmp_path / "model"))
    client = TestClient(app)
    assert client.get("/health").json()["data"]["ok"] is True
    assert client.post("/demo/generate", json={"seed": 31}).status_code == 200
    assert client.post("/model/train", json={"seed": 31}).status_code == 200
    assert client.post("/detect").status_code == 200
    anomalies = client.get("/anomalies").json()["anomalies"]
    assert anomalies
    assert client.get("/summary").json()["data"]["anomaly_count"] == len(anomalies)

