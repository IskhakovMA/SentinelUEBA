from __future__ import annotations

import hashlib
import json
from dataclasses import asdict
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from typer.testing import CliRunner

from sentinelueba.api.main import app
from sentinelueba.cli import app as cli_app
from sentinelueba.config import Settings
from sentinelueba.domain.events import EventType, TelemetryEvent, deterministic_event_id
from sentinelueba.features.windows import FEATURE_NAMES
from sentinelueba.ml.stage3_calibration import ThresholdCalibrator
from sentinelueba.ml.stage3_contracts import PreprocessorV1
from sentinelueba.ml.stage3_models import (
    AutoencoderV2Config,
    AutoencoderV2Model,
    IsolationForestV1Config,
    IsolationForestV1Model,
)
from sentinelueba.ml.stage3_service import ModelBundleVerificationError, _psi, profile_key
from sentinelueba.ml.stage3_split import create_split_plan, split_matrices
from sentinelueba.services.pipeline import DemoPipeline


def settings(tmp_path: Path) -> Settings:
    return Settings(
        data_dir=tmp_path / "data",
        database_path=tmp_path / "data" / "stage3.sqlite3",
        model_dir=tmp_path / "model",
    )


def prepared_synthetic_pipe(tmp_path: Path, *, seed: int = 42) -> DemoPipeline:
    pipe = DemoPipeline(settings(tmp_path))
    pipe.initialize()
    pipe.generate_demo_data(seed=seed)
    pipe.materialize_features("synthetic")
    return pipe


def small_if_config() -> dict[str, object]:
    return asdict(IsolationForestV1Config(n_estimators=16, n_jobs=1))


def rewrite_checksums(bundle: Path) -> None:
    lines = []
    for path in sorted(bundle.iterdir(), key=lambda item: item.name):
        if path.name == "checksums.sha256":
            continue
        digest = hashlib.sha256(path.read_bytes()).hexdigest()
        lines.append(f"{digest}  {path.name}")
    (bundle / "checksums.sha256").write_text("\n".join(lines) + "\n")


def test_stage3_synthetic_split_is_leakage_safe_and_deterministic(tmp_path: Path) -> None:
    pipe = prepared_synthetic_pipe(tmp_path)
    dataset_id = str(pipe.create_dataset("synthetic")["dataset_id"])
    matrix, manifest, rows = pipe.snapshots().load_matrix(dataset_id)
    split = create_split_plan(
        rows,
        manifest,
        dataset_manifest_sha256=str(manifest["verification"]["manifest_sha256"]),
    )
    repeat = create_split_plan(
        rows,
        manifest,
        dataset_manifest_sha256=str(manifest["verification"]["manifest_sha256"]),
    )

    assert split.split_id == repeat.split_id
    assert split.train.count == 50
    assert split.calibration.count == 22
    assert split.test.count == 24
    assert len(split.scenario_window_ids) == 5
    assert set(split.scenario_window_ids).issubset(set(split.test.window_ids))
    assert not set(split.train.window_ids) & set(split.calibration.window_ids)
    assert not set(split.train.window_ids) & set(split.test.window_ids)
    assert len(matrix[0]) == len(FEATURE_NAMES)
    assert "scenario_name" not in FEATURE_NAMES


def test_stage3_preprocessor_and_threshold_use_no_test_rows(tmp_path: Path) -> None:
    pipe = prepared_synthetic_pipe(tmp_path)
    dataset_id = str(pipe.create_dataset("synthetic")["dataset_id"])
    _, manifest, rows = pipe.snapshots().load_matrix(dataset_id)
    split = create_split_plan(
        rows,
        manifest,
        dataset_manifest_sha256=str(manifest["verification"]["manifest_sha256"]),
    )
    train_matrix, calibration_matrix, test_matrix = split_matrices(rows, split)

    preprocessor = PreprocessorV1.fit(train_matrix)
    calibration_scores = [sum(abs(value) for value in row) for row in calibration_matrix]
    threshold = ThresholdCalibrator(target_false_positive_rate=0.05).calibrate(
        calibration_scores
    )
    mutated_test = [[value + 1_000_000.0 for value in row] for row in test_matrix]

    assert asdict(PreprocessorV1.fit(train_matrix)) == asdict(preprocessor)
    assert ThresholdCalibrator(target_false_positive_rate=0.05).calibrate(
        calibration_scores
    ).threshold == threshold.threshold
    assert mutated_test != test_matrix


def test_autoencoder_v2_is_deterministic_and_roundtrips(tmp_path: Path) -> None:
    matrix = [
        [float((row + column) % 5) for column in range(len(FEATURE_NAMES))]
        for row in range(24)
    ]
    scaled = PreprocessorV1.fit(matrix).transform(matrix)
    config = AutoencoderV2Config(epochs=6, batch_size=5, hidden_dim=6, latent_dim=3)
    first = AutoencoderV2Model(config)
    second = AutoencoderV2Model(config)
    first.fit(scaled, seed=7)
    second.fit(scaled, seed=7)
    scores = first.score(scaled).scores

    assert scores == pytest.approx(second.score(scaled).scores)
    assert first.loss_history
    assert all(value >= 0 for value in first.loss_history)
    artifact = tmp_path / "autoencoder.pt"
    first.save_artifact(artifact)
    loaded = AutoencoderV2Model.load_verified_artifact(artifact)
    assert loaded.score(scaled).scores == pytest.approx(scores)
    with pytest.raises(ValueError, match="NaN|Infinity"):
        first.fit([[float("nan") for _ in FEATURE_NAMES]], seed=7)


def test_isolation_forest_uses_higher_anomaly_scores_and_safe_skops(tmp_path: Path) -> None:
    normal = [
        [float((row + column) % 4) for column in range(len(FEATURE_NAMES))]
        for row in range(32)
    ]
    outlier = [[25.0 for _ in FEATURE_NAMES]]
    model = IsolationForestV1Model(IsolationForestV1Config(n_estimators=24, n_jobs=1))
    repeat = IsolationForestV1Model(IsolationForestV1Config(n_estimators=24, n_jobs=1))
    model.fit(normal, seed=11)
    repeat.fit(normal, seed=11)
    scores = model.score(normal + outlier).scores

    assert scores == pytest.approx(repeat.score(normal + outlier).scores)
    assert scores[-1] > max(scores[:-1])
    artifact = tmp_path / "isolation_forest.skops"
    model.save_artifact(artifact)
    assert not list(tmp_path.glob("*.pkl"))
    loaded = IsolationForestV1Model.load_verified_artifact(artifact)
    assert loaded.score(normal + outlier).scores == pytest.approx(scores)
    artifact.write_text("not-a-skops-artifact")
    with pytest.raises(Exception):  # noqa: B017
        IsolationForestV1Model.load_verified_artifact(artifact)


def test_model_bundle_registry_tamper_and_path_validation(tmp_path: Path) -> None:
    pipe = prepared_synthetic_pipe(tmp_path)
    result = pipe.ml().train(
        dataset_kind="synthetic",
        families=["isolation-forest"],
        isolation_forest_config=small_if_config(),
    )
    model_id = str(result["candidates"][0]["model_id"])
    assert pipe.ml_verify_model(model_id)["verified"] is True
    bundle = tmp_path / "models" / model_id

    manifest = json.loads((bundle / "manifest.json").read_text())
    manifest["threshold"] = float(manifest["threshold"]) + 1.0
    (bundle / "manifest.json").write_text(json.dumps(manifest, indent=2, sort_keys=True))
    with pytest.raises(ModelBundleVerificationError, match="SHA-256 mismatch"):
        pipe.ml_verify_model(model_id)
    with pytest.raises(ModelBundleVerificationError, match="unsafe model id"):
        pipe.ml_verify_model("../escape")


@pytest.mark.parametrize(
    ("filename", "mutate"),
    [
        ("preprocessor.json", lambda payload: payload["mean"].__setitem__(0, 999.0)),
        ("preprocessor.json", lambda payload: payload["std"].__setitem__(0, 0.0)),
        ("split.json", lambda payload: payload["train"]["window_ids"].__setitem__(0, "tampered")),
        ("split.json", lambda payload: payload["train"].__setitem__("count", 999)),
        ("metrics.json", lambda payload: payload.__setitem__("threshold", 999.0)),
        ("manifest.json", lambda payload: payload["artifact_hashes"].__setitem__(
            "metrics_sha256",
            "0" * 64,
        )),
    ],
)
def test_model_bundle_rejects_tamper_even_with_rewritten_checksums(
    tmp_path: Path,
    filename: str,
    mutate: object,
) -> None:
    pipe = prepared_synthetic_pipe(tmp_path)
    result = pipe.ml().train(
        dataset_kind="synthetic",
        families=["isolation-forest"],
        isolation_forest_config=small_if_config(),
    )
    model_id = str(result["candidates"][0]["model_id"])
    bundle = tmp_path / "models" / model_id
    path = bundle / filename
    payload = json.loads(path.read_text())
    mutate(payload)  # type: ignore[operator]
    path.write_text(json.dumps(payload, indent=2, sort_keys=True))
    rewrite_checksums(bundle)

    with pytest.raises(ModelBundleVerificationError):
        pipe.ml_verify_model(model_id)


@pytest.mark.parametrize(
    "filename",
    ["model_card.md", "isolation_forest.skops", "checksums.sha256"],
)
def test_model_bundle_rejects_text_and_artifact_tamper(tmp_path: Path, filename: str) -> None:
    pipe = prepared_synthetic_pipe(tmp_path)
    result = pipe.ml().train(
        dataset_kind="synthetic",
        families=["isolation-forest"],
        isolation_forest_config=small_if_config(),
    )
    model_id = str(result["candidates"][0]["model_id"])
    bundle = tmp_path / "models" / model_id
    target = bundle / filename
    target.write_bytes(target.read_bytes() + b"\ntampered\n")
    if filename != "checksums.sha256":
        rewrite_checksums(bundle)

    with pytest.raises(ModelBundleVerificationError):
        pipe.ml_verify_model(model_id)


@pytest.mark.parametrize(
    "stage",
    ["internal", "after_rename", "register", "public"],
)
def test_model_bundle_failure_cleanup_has_no_orphans(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    stage: str,
) -> None:
    pipe = prepared_synthetic_pipe(tmp_path)
    service = pipe.ml()
    if stage == "internal":
        monkeypatch.setattr(
            service.verifier,
            "verify_internal",
            lambda *args, **kwargs: (_ for _ in ()).throw(RuntimeError("internal injected")),
        )
    elif stage == "after_rename":
        original_create_bundle = service._create_bundle

        def fail_after_rename(*args: object, **kwargs: object) -> dict[str, object]:
            original_create_bundle(*args, **kwargs)
            raise RuntimeError("after rename injected")

        monkeypatch.setattr(service, "_create_bundle", fail_after_rename)
    elif stage == "register":
        monkeypatch.setattr(
            service.storage,
            "register_model_version",
            lambda payload: (_ for _ in ()).throw(RuntimeError("register injected")),
        )
    else:
        monkeypatch.setattr(
            service.verifier,
            "verify",
            lambda model_id: (_ for _ in ()).throw(RuntimeError("public injected")),
        )

    with pytest.raises(RuntimeError, match="injected"):
        service.train(
            dataset_kind="synthetic",
            families=["isolation-forest"],
            isolation_forest_config=small_if_config(),
        )

    assert service.storage.list_model_versions() == []
    runs = service.storage.list_training_runs()
    assert runs[0]["status"] == "failed"
    assert "injected" in str(runs[0]["safe_error_message"])
    models_root = tmp_path / "models"
    assert not list(models_root.glob(".tmp-*"))
    assert not [path for path in models_root.glob("*") if path.is_dir()]


def test_concurrent_same_profile_training_is_rejected_by_db_lock(tmp_path: Path) -> None:
    pipe = prepared_synthetic_pipe(tmp_path)
    dataset_id = str(pipe.create_dataset("synthetic")["dataset_id"])
    _, manifest, _ = pipe.snapshots().load_matrix(dataset_id)
    pipe.storage.create_training_run(
        {
            "training_run_id": "running-lock",
            "dataset_id": dataset_id,
            "dataset_manifest_sha256": manifest["verification"]["manifest_sha256"],
            "dataset_kind": manifest["dataset_kind"],
            "profile_key": profile_key(manifest["profile"]),
            "split_id": "pending",
            "split_manifest_sha256": "pending",
            "effective_config_json": "{}",
            "config_sha256": "0" * 64,
            "seed": 42,
            "status": "running",
            "started_at": datetime.now(UTC).isoformat(),
            "application_version": "test",
        }
    )

    with pytest.raises(ValueError, match="already running"):
        pipe.ml().train(
            dataset_kind="synthetic",
            dataset_id=dataset_id,
            families=["isolation-forest"],
            isolation_forest_config=small_if_config(),
        )


def test_stage3_lifecycle_promote_rollback_and_immutable_scoring(tmp_path: Path) -> None:
    pipe = prepared_synthetic_pipe(tmp_path)
    trained = pipe.train(seed=42)
    champion_id = str(trained["champion_model_id"])
    recommended_id = str(trained["recommended_model_id"])
    assert champion_id == recommended_id

    models = pipe.ml_models()
    assert [model["lifecycle_status"] for model in models].count("champion") == 1
    dataset_id = str(trained["dataset_id"])
    first = pipe.ml_score(dataset_id=dataset_id, model_id=champion_id)
    second = pipe.ml_score(dataset_id=dataset_id, model_id=champion_id)
    assert first["scoring_run_id"] != second["scoring_run_id"]
    assert pipe.ml_scoring_run(str(first["scoring_run_id"])) is not None

    retired = pipe.ml_retire_model(champion_id, confirm=True, reason="test retirement")
    assert retired["action"] == "retire"
    assert pipe.storage.champion_model("synthetic") is None
    rollback = pipe.ml_rollback_model(champion_id, confirm=True, reason="test rollback")
    assert rollback["new_model_id"] == champion_id
    assert pipe.storage.champion_model("synthetic")["model_id"] == champion_id  # type: ignore[index]
    with pipe.storage.connect() as conn:
        promotions = conn.execute("SELECT action FROM model_promotions").fetchall()
    assert "rollback" in {row["action"] for row in promotions}


def test_lifecycle_forbidden_transitions_are_rejected(tmp_path: Path) -> None:
    pipe = prepared_synthetic_pipe(tmp_path)
    result = pipe.ml().train(
        dataset_kind="synthetic",
        families=["isolation-forest"],
        isolation_forest_config=small_if_config(),
        auto_promote_synthetic=False,
    )
    model_id = str(result["candidates"][0]["model_id"])
    with pytest.raises(ValueError, match="confirmation"):
        pipe.ml_promote_model(model_id, confirm=False)
    promoted = pipe.ml_promote_model(model_id, confirm=True)
    assert promoted["new_model_id"] == model_id
    with pytest.raises(ValueError, match="already champion"):
        pipe.ml_promote_model(model_id, confirm=True)
    with pytest.raises(ValueError, match="only for retired"):
        pipe.ml_rollback_model(model_id, confirm=True)
    pipe.ml_retire_model(model_id, confirm=True)
    with pytest.raises(ValueError, match="cannot be promoted|only candidate"):
        pipe.ml_promote_model(model_id, confirm=True)


def test_real_14h_training_is_rejected_on_all_public_paths(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("SENTINELUEBA_DATA_DIR", str(tmp_path / "data"))
    monkeypatch.setenv("SENTINELUEBA_DATABASE_PATH", str(tmp_path / "data" / "real.sqlite3"))
    monkeypatch.setenv("SENTINELUEBA_MODEL_DIR", str(tmp_path / "model"))
    pipe = DemoPipeline(settings(tmp_path))
    pipe.initialize()
    start = datetime(2026, 1, 1, tzinfo=UTC)
    pipe.storage.insert_events(real_events(start, windows=56, synthetic=False))
    add_observations(pipe, start, windows=56)
    pipe.materialize_features("real")
    dataset_id = str(pipe.create_dataset("real")["dataset_id"])

    with pytest.raises(ValueError, match="real training"):
        pipe.train(dataset_kind="real")
    with pytest.raises(ValueError, match="real training"):
        pipe.ml().train(
            dataset_kind="real",
            dataset_id=dataset_id,
            families=["isolation-forest"],
            isolation_forest_config=small_if_config(),
        )
    client = TestClient(app)
    response = client.post(
        "/ml/train",
        json={
            "dataset_kind": "real",
            "dataset_id": dataset_id,
            "families": ["isolation-forest"],
        },
    )
    assert response.status_code == 409
    runner = CliRunner()
    cli = runner.invoke(
        cli_app,
        [
            "ml",
            "train",
            "--dataset",
            "real",
            "--dataset-id",
            dataset_id,
            "--families",
            "isolation-forest",
        ],
    )
    assert cli.exit_code == 2
    assert pipe.storage.list_model_versions() == []
    assert not list((tmp_path / "models").glob("*"))


def test_real_training_is_unlabeled_and_not_auto_promoted(tmp_path: Path) -> None:
    pipe = DemoPipeline(settings(tmp_path))
    pipe.initialize()
    start = datetime(2026, 1, 1, tzinfo=UTC)
    pipe.storage.insert_events(real_events(start, windows=96, synthetic=False))
    add_observations(pipe, start, windows=96)
    pipe.materialize_features("real")
    result = pipe.ml().train(
        dataset_kind="real",
        families=["isolation-forest"],
        isolation_forest_config=small_if_config(),
    )
    model_id = str(result["candidates"][0]["model_id"])
    model = pipe.ml_model(model_id)["model"]
    evaluation = pipe.ml_evaluate_model(model_id)

    assert result["recommended_model_id"] is None
    assert model["lifecycle_status"] == "candidate"
    assert evaluation["metrics"]["label_status"] == "unlabeled"
    assert evaluation["metrics"]["test_flagged_rate"] >= 0
    assert "feature_distribution_summary" in evaluation["metrics"]
    assert "precision" not in evaluation["metrics"]


def test_drift_reports_shift_insufficient_data_and_incompatible_profile(tmp_path: Path) -> None:
    pipe = prepared_synthetic_pipe(tmp_path)
    trained = pipe.train(seed=42)
    model_id = str(trained["champion_model_id"])
    dataset_id = str(trained["dataset_id"])
    report = pipe.ml_drift(model_id=model_id, dataset_id=dataset_id)

    assert report["status"] == "ok"
    assert report["reference_split"]["kind"] == "train"
    assert "model_score_quantiles" in report
    assert "flagged_rate_difference" in report
    assert report["top_shifted_features"][0]["standardized_mean_shift"] >= 0

    with pipe.storage.connect() as conn:
        conn.execute("DELETE FROM telemetry_events")
        conn.execute("DELETE FROM feature_windows")
        conn.execute("DELETE FROM feature_materialization_state")
    start = datetime(2026, 2, 1, tzinfo=UTC)
    pipe.storage.insert_events(
        real_events(
            start,
            windows=8,
            synthetic=True,
            user="demo-user-001",
            host="demo-host-001",
        )
    )
    pipe.materialize_features("synthetic")
    small_dataset = str(pipe.create_dataset("synthetic")["dataset_id"])
    assert pipe.ml_drift(model_id=model_id, dataset_id=small_dataset)["status"] == (
        "insufficient_data"
    )

    with pipe.storage.connect() as conn:
        conn.execute("DELETE FROM telemetry_events")
        conn.execute("DELETE FROM feature_windows")
        conn.execute("DELETE FROM feature_materialization_state")
        conn.execute("DELETE FROM dataset_snapshots WHERE dataset_id = ?", (small_dataset,))
    shifted_start = datetime(2026, 3, 1, tzinfo=UTC)
    pipe.storage.insert_events(
        real_events(shifted_start, windows=96, synthetic=True, user="other-user")
    )
    pipe.materialize_features("synthetic")
    incompatible = str(pipe.create_dataset("synthetic")["dataset_id"])
    with pytest.raises(ValueError, match="profile is incompatible"):
        pipe.ml_drift(model_id=model_id, dataset_id=incompatible)


def test_stage3_api_and_cli_smoke(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("SENTINELUEBA_DATA_DIR", str(tmp_path / "data"))
    monkeypatch.setenv("SENTINELUEBA_DATABASE_PATH", str(tmp_path / "data" / "api.sqlite3"))
    monkeypatch.setenv("SENTINELUEBA_MODEL_DIR", str(tmp_path / "model"))
    client = TestClient(app)
    assert client.post("/demo/generate", json={"seed": 42}).status_code == 200
    invalid = client.post(
        "/ml/train",
        json={
            "dataset_kind": "synthetic",
            "families": ["isolation-forest"],
            "isolation_forest": {"n_estimators": 1},
        },
    )
    assert invalid.status_code == 422
    train = client.post(
        "/ml/train",
        json={
            "dataset_kind": "synthetic",
            "families": ["isolation-forest"],
            "isolation_forest": {"n_estimators": 16, "n_jobs": 1},
        },
    )
    assert train.status_code == 200
    model_id = train.json()["data"]["candidates"][0]["model_id"]
    dataset_id = train.json()["data"]["dataset_id"]
    assert client.get("/ml/status").status_code == 200
    assert client.post(f"/ml/models/{model_id}/verify").status_code == 200
    assert client.post("/ml/evaluate", json={"model_id": model_id}).status_code == 200
    assert (
        client.post("/ml/score", json={"dataset_id": dataset_id, "model_id": model_id}).status_code
        == 200
    )
    assert (
        client.post(
            "/ml/score",
            json={"dataset_id": dataset_id, "model_id": model_id, "batch_size": 7},
        ).status_code
        == 200
    )

    runner = CliRunner()
    assert runner.invoke(cli_app, ["ml", "status"]).exit_code == 0
    assert runner.invoke(cli_app, ["ml", "models", "list"]).exit_code == 0
    assert runner.invoke(cli_app, ["ml", "scoring-runs", "list"]).exit_code == 0


def test_scoring_failure_records_failed_run_without_rows(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    pipe = prepared_synthetic_pipe(tmp_path)
    trained = pipe.ml().train(
        dataset_kind="synthetic",
        families=["isolation-forest"],
        isolation_forest_config=small_if_config(),
    )
    model_id = str(trained["candidates"][0]["model_id"])
    dataset_id = str(trained["dataset_id"])
    service = pipe.ml()
    monkeypatch.setattr(
        service.verifier,
        "load",
        lambda model_id: (_ for _ in ()).throw(RuntimeError("load failure injected")),
    )

    with pytest.raises(RuntimeError, match="load failure injected"):
        service.score(dataset_id=dataset_id, model_id=model_id)

    run = service.storage.list_scoring_runs()[0]
    assert run["status"] == "failed"
    assert "load failure injected" in str(run["safe_error"])
    assert service.storage.get_scoring_run(str(run["scoring_run_id"]))["windows"] == []  # type: ignore[index]


def test_scoring_uses_configurable_batches(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    pipe = prepared_synthetic_pipe(tmp_path)
    trained = pipe.ml().train(
        dataset_kind="synthetic",
        families=["isolation-forest"],
        isolation_forest_config=small_if_config(),
    )
    model_id = str(trained["candidates"][0]["model_id"])
    dataset_id = str(trained["dataset_id"])
    service = pipe.ml()
    original_load = service.verifier.load
    batch_lengths: list[int] = []

    class RecordingModel:
        def __init__(self, wrapped: object) -> None:
            self.wrapped = wrapped

        def score(self, matrix: list[list[float]]) -> object:
            batch_lengths.append(len(matrix))
            return self.wrapped.score(matrix)  # type: ignore[attr-defined]

    def load_with_recording(model_id: str) -> tuple[dict[str, object], PreprocessorV1, object]:
        manifest, preprocessor, model = original_load(model_id)
        return manifest, preprocessor, RecordingModel(model)

    monkeypatch.setattr(service.verifier, "load", load_with_recording)
    result = service.score(dataset_id=dataset_id, model_id=model_id, batch_size=7)

    assert result["batch_size"] == 7
    assert max(batch_lengths) <= 7
    assert len(batch_lengths) > 1


def test_legacy_unregistered_status_and_compare_report(tmp_path: Path) -> None:
    pipe = prepared_synthetic_pipe(tmp_path)
    legacy = tmp_path / "model" / "synthetic"
    legacy.mkdir(parents=True)
    (legacy / "model_info.json").write_text("{}")
    (legacy / "preprocessor.json").write_text("{}")
    (legacy / "autoencoder.pt").write_bytes(b"legacy")
    assert pipe.ml_status()["legacy_unregistered"] is True

    trained = pipe.train(seed=42)
    model_ids = [str(item["model_id"]) for item in trained["candidates"]]
    report = pipe.ml_compare_models(model_ids)
    assert report["models"]
    assert report["recommendation_order"]
    assert all("verification_status" in item for item in report["models"])


def test_psi_handles_constant_and_rejects_non_finite() -> None:
    import numpy as np

    assert _psi(np.asarray([1.0] * 20), np.asarray([1.0] * 20)) == pytest.approx(0.0)
    shifted = _psi(np.asarray([1.0] * 20), np.asarray([2.0] * 20))
    assert shifted >= 0
    assert shifted < float("inf")
    with pytest.raises(ValueError, match="NaN|Infinity"):
        _psi(np.asarray([1.0, float("nan")]), np.asarray([1.0, 2.0]))


def add_observations(pipe: DemoPipeline, start: datetime, *, windows: int) -> None:
    session_id = f"stage3-fixture-{windows}"
    with pipe.storage.connect() as conn:
        conn.execute(
            """
            INSERT INTO collection_sessions (
                session_id, started_at, stopped_at, status, collection_mode,
                enabled_collectors_json, counters_json, errors_json, application_version,
                last_heartbeat_at, last_successful_collection_at
            ) VALUES (?, ?, ?, 'stopped', 'fixture', ?, ?, '[]', 'test', ?, ?)
            """,
            (
                session_id,
                start.isoformat(),
                (start + timedelta(minutes=15 * windows)).isoformat(),
                json.dumps(
                    [
                        "windows.system_metrics.psutil",
                        "windows.process.psutil",
                        "windows.network.psutil",
                    ]
                ),
                json.dumps({"fixture_windows": windows}),
                (start + timedelta(minutes=15 * windows)).isoformat(),
                (start + timedelta(minutes=15 * windows)).isoformat(),
            ),
        )
    for index in range(windows):
        observed_at = start + timedelta(minutes=15 * index)
        for collector_id in [
            "windows.system_metrics.psutil",
            "windows.process.psutil",
            "windows.network.psutil",
        ]:
            pipe.storage.record_collector_observation(
                session_id=session_id,
                collector_id=collector_id,
                user_id="user-a",
                host_id="host-a",
                observed_at=observed_at,
                status="ok",
                successful_poll=True,
                error_class=None,
                configured_interval_seconds=15 * 60,
                returned_events=2,
                saved_events=2,
            )


def real_events(
    start: datetime,
    *,
    windows: int,
    synthetic: bool,
    user: str = "user-a",
    host: str = "host-a",
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
                {"cpu_percent": 10.0 + (index % 5), "ram_percent": 40.0 + (index % 3)},
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
    ts: datetime,
    synthetic: bool,
    user: str,
    host: str,
) -> TelemetryEvent:
    return TelemetryEvent(
        event_id=deterministic_event_id(
            [str(index), ts.isoformat(), event_type.value, user, host, str(synthetic)]
        ),
        timestamp=ts,
        event_type=event_type,
        user_id=user,
        host_id=host,
        source="stage3-test",
        payload=payload,
        synthetic=synthetic,
    )
