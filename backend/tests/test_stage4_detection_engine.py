from __future__ import annotations

import json
import sqlite3
import time
from dataclasses import asdict
from datetime import datetime, timedelta
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from typer.testing import CliRunner

from sentinelueba.api.main import app
from sentinelueba.cli import app as cli_app
from sentinelueba.config import Settings
from sentinelueba.detection.contracts import DetectionInput
from sentinelueba.detection.policies import DEFAULT_POLICY_ID, RULES_ONLY_POLICY_ID
from sentinelueba.detection.service import DetectionEngineError, model_strength
from sentinelueba.features.windows import FEATURE_NAMES
from sentinelueba.ml.stage3_models import AutoencoderV2Config
from sentinelueba.services.pipeline import DemoPipeline
from sentinelueba.storage.sqlite import DB_SCHEMA_VERSION, SchemaIntegrityError, SQLiteStorage


def settings(tmp_path: Path) -> Settings:
    return Settings(
        data_dir=tmp_path / "data",
        database_path=tmp_path / "data" / "stage4.sqlite3",
        model_dir=tmp_path / "model",
    )


def prepared_pipe(tmp_path: Path) -> DemoPipeline:
    pipe = DemoPipeline(settings(tmp_path))
    pipe.initialize()
    pipe.generate_demo_data(seed=42)
    pipe.materialize_features("synthetic")
    return pipe


def scenario_evaluations(
    pipe: DemoPipeline,
    result: dict[str, object],
) -> dict[str, dict[str, object]]:
    run_ids = [run_id(result)]
    if result.get("child_run_ids"):
        run_ids = [str(item) for item in result["child_run_ids"]]  # type: ignore[index]
    evaluations: dict[str, dict[str, object]] = {}
    for detection_run_id in run_ids:
        run = pipe.detection_run(detection_run_id)
        assert run is not None
        evaluations.update({item["window_start"]: item for item in run["evaluations"]})
    manifest = pipe.generate_demo_data(seed=42)["scenario_manifest"]
    return {item["name"]: evaluations[item["window_start"]] for item in manifest}


DETECTION_TABLES = (
    "detection_runs",
    "detection_evaluations",
    "findings",
    "finding_occurrences",
    "finding_state_history",
    "detection_suppressions",
    "detection_watermarks",
    "detection_worker_leases",
)


def detection_table_counts(storage: SQLiteStorage) -> dict[str, int]:
    with storage.connect() as conn:
        return {
            table: int(conn.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0])
            for table in DETECTION_TABLES
        }

def run_id(result: dict[str, object]) -> str:
    if result.get("detection_run_id") is not None:
        return str(result["detection_run_id"])
    children = result.get("child_run_ids")
    assert isinstance(children, list)
    assert len(children) == 1
    return str(children[0])


def test_stage4_schema_v10_fresh_repeat_and_corrupt_claimed_v10(tmp_path: Path) -> None:
    storage = SQLiteStorage(tmp_path / "fresh.sqlite3")
    storage.initialize()
    storage.initialize()

    assert storage.status()["schema_version"] == DB_SCHEMA_VERSION == 10
    with storage.connect() as conn:
        tables = {
            row["name"]
            for row in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")
        }
    assert {
        "detection_policies",
        "detection_runs",
        "detection_evaluations",
        "findings",
        "finding_occurrences",
        "finding_state_history",
        "detection_suppressions",
        "detection_watermarks",
        "detection_worker_leases",
        "detection_policy_activations",
    }.issubset(tables)

    corrupt = tmp_path / "corrupt.sqlite3"
    with sqlite3.connect(corrupt) as conn:
        conn.execute("CREATE TABLE schema_version (version INTEGER PRIMARY KEY, applied_at TEXT)")
        conn.execute("INSERT INTO schema_version(version, applied_at) VALUES (10, 'now')")
    with pytest.raises(SchemaIntegrityError):
        SQLiteStorage(corrupt).initialize()


def test_detection_input_contract_excludes_raw_identity_and_payload(tmp_path: Path) -> None:
    pipe = prepared_pipe(tmp_path)
    window = pipe.storage.list_feature_windows(dataset_kind="synthetic")[0]
    detection_input = pipe.detection()._window_input(window)

    assert isinstance(detection_input, DetectionInput)
    assert detection_input.feature_names == tuple(FEATURE_NAMES)
    assert set(DetectionInput.model_fields) == {
        "window_id",
        "dataset_kind",
        "profile_key",
        "window_start",
        "window_end",
        "feature_schema_version",
        "feature_names",
        "feature_values",
        "quality",
        "feature_input_hash",
    }
    dumped = detection_input.model_dump(mode="json")
    assert "user_id" not in dumped
    assert "host_id" not in dumped
    assert "payload" not in dumped
    assert "scenario" not in dumped


def test_stage4_hybrid_detects_all_synthetic_scenarios_without_labels(tmp_path: Path) -> None:
    pipe = prepared_pipe(tmp_path)
    trained = pipe.ml().train(
        dataset_kind="synthetic",
        families=["autoencoder"],
        autoencoder_config=asdict(AutoencoderV2Config(epochs=6, plateau_patience=4)),
    )
    model_id = str(trained["candidates"][0]["model_id"])
    assert pipe.storage.champion_model("synthetic")["model_id"] == model_id  # type: ignore[index]

    result = pipe.detection_run_once(dataset_kind="synthetic")
    scenarios = scenario_evaluations(pipe, result)

    child = pipe.detection_run(run_id(result))
    assert child is not None
    assert child["model_id"] == model_id
    assert result["evaluated_count"] == 96
    assert result["child_run_ids"] == [run_id(result)]
    assert set(scenarios) == {
        "rare_process",
        "outbound_connection_spike",
        "atypical_time_activity",
        "cpu_ram_spike",
        "failed_login_series",
    }
    assert all(item["status"] == "finding" for item in scenarios.values())
    for evaluation in scenarios.values():
        decision_blob = json.dumps(evaluation["decision"], sort_keys=True)
        assert "scenario" not in decision_blob
        assert "demo-user" not in decision_blob
        assert "demo-host" not in decision_blob
        assert "payload" not in decision_blob
        assert "finding is an analyst triage item" in decision_blob.lower()


def test_stage4_idempotency_makes_second_same_run_noop(tmp_path: Path) -> None:
    pipe = prepared_pipe(tmp_path)
    first = pipe.detection_run_once(dataset_kind="synthetic", rules_only=True)
    second = pipe.detection_run_once(dataset_kind="synthetic", rules_only=True)

    assert first["evaluated_count"] == 96
    assert second["evaluated_count"] == 0
    assert second["examined_count"] == 0
    assert second["child_run_ids"] == [run_id(second)]
    assert pipe.detection_status()["active_policy"]["policy_id"] == DEFAULT_POLICY_ID


def test_stage4_signal_suppression_preserves_audit_without_finding(tmp_path: Path) -> None:
    pipe = prepared_pipe(tmp_path)
    rare_window = next(
        window
        for window in pipe.storage.list_feature_windows(dataset_kind="synthetic")
        if window["window_start"] == "2026-01-06T00:00:00+00:00"
    )
    profile_key = pipe.detection()._profile_key_for_window(rare_window)
    suppression = pipe.detection_create_suppression(
        scope="signal_for_profile",
        reason="test suppression",
        ttl_minutes=60,
        profile_key=profile_key,
        signal_id="rare-process-v1",
    )
    result = pipe.detection_run_once(dataset_kind="synthetic", rules_only=True)
    scenarios = scenario_evaluations(pipe, result)

    assert suppression["active"] == 1
    assert scenarios["rare_process"]["status"] == "suppressed"
    assert scenarios["rare_process"]["finding_id"] is None
    assert pipe.detection_suppressions()[0]["reason"] == "test suppression"


def test_stage4_v10_exact_profile_policy_and_worker_contracts(tmp_path: Path) -> None:
    pipe = prepared_pipe(tmp_path)
    profile = pipe.storage.list_detection_profiles(dataset_kind="synthetic")[0]

    policy = pipe.detection_policy(RULES_ONLY_POLICY_ID)
    with pytest.raises(DetectionEngineError, match="confirm=true"):
        pipe.detection_activate_policy(RULES_ONLY_POLICY_ID)
    activated = pipe.detection_activate_policy(
        RULES_ONLY_POLICY_ID,
        confirm=True,
        reason="activate rules-only regression policy",
    )
    assert activated["policy_hash"] == policy["policy_hash"]

    result = pipe.detection_run_once(dataset_kind="synthetic", profile=profile)
    assert result["detection_run_id"] is not None
    assert result["child_run_ids"] == []
    assert result["model_id"] is None
    assert result["policy_id"] == RULES_ONLY_POLICY_ID
    assert result["evaluated_count"] == 96

    with pipe.storage.connect() as conn:
        run = conn.execute(
            "SELECT * FROM detection_runs WHERE detection_run_id = ?",
            (result["detection_run_id"],),
        ).fetchone()
        evaluations = conn.execute(
            "SELECT DISTINCT profile_key, model_id, policy_hash FROM detection_evaluations"
        ).fetchall()
        activations = conn.execute("SELECT COUNT(*) FROM detection_policy_activations").fetchone()
    assert run["profile_key"] == profile
    assert run["policy_mode"] == "rules_only"
    assert run["examined_windows"] == 96
    assert {(row["profile_key"], row["model_id"], row["policy_hash"]) for row in evaluations} == {
        (profile, "__rules_only__", policy["policy_hash"])
    }
    assert activations[0] == 1

    start = "2026-01-06T00:00:00+00:00"
    end = "2026-01-07T00:00:00+00:00"
    with pytest.raises(DetectionEngineError, match="explicit registered policy id"):
        pipe.detection_backfill(
            dataset_kind="synthetic",
            start=datetime.fromisoformat(start),
            end=datetime.fromisoformat(end),
            confirm=True,
        )
    with pytest.raises(DetectionEngineError, match="confirm_advance_watermark=true"):
        pipe.detection_backfill(
            dataset_kind="synthetic",
            policy_id=RULES_ONLY_POLICY_ID,
            start=datetime.fromisoformat(start),
            end=datetime.fromisoformat(end),
            confirm=True,
            advance_watermark=True,
        )

    with pytest.raises(DetectionEngineError, match="known Stage 4 signal"):
        pipe.detection_create_suppression(
            scope="signal_for_profile",
            reason="bad signal",
            ttl_minutes=5,
            profile_key=profile,
            signal_id="unknown-rule",
        )
    suppression = pipe.detection_create_suppression(
        scope="signal_for_profile",
        reason="exact suppress",
        ttl_minutes=5,
        profile_key=profile,
        signal_id="rare-process-v1",
    )
    with pytest.raises(DetectionEngineError, match="confirm=true"):
        pipe.detection_revoke_suppression(str(suppression["suppression_id"]))
    revoked = pipe.detection_revoke_suppression(
        str(suppression["suppression_id"]),
        confirm=True,
    )
    assert revoked["revoked"] is True

    worker = pipe.detection_worker_run_foreground(
        dataset_kind="synthetic",
        max_windows=1,
        single_cycle=True,
    )
    assert worker["worker"]["worker_key"] == "stage4|synthetic|*"
    assert "owner_id" not in worker["worker"]
    assert "config_json" not in worker["worker"]
    assert worker["runs"]


def test_stage4_dry_run_evaluates_without_db_writes(tmp_path: Path) -> None:
    pipe = prepared_pipe(tmp_path)
    before = detection_table_counts(pipe.storage)

    dry = pipe.detection_run_once(dataset_kind="synthetic", rules_only=True, dry_run=True)

    assert dry["status"] == "dry_run"
    assert dry["detection_run_id"] is None
    assert dry["examined_count"] == 96
    assert dry["evaluated_count"] == 96
    assert dry["would_create_findings"] >= 5
    assert sum(dry["risk_counts"].values()) == 96
    assert dry["sample_decisions"]
    assert detection_table_counts(pipe.storage) == before

    normal = pipe.detection_run_once(dataset_kind="synthetic", rules_only=True)
    assert normal["evaluated_count"] == dry["evaluated_count"]
    assert normal["finding_count"] == dry["would_create_findings"]


def test_stage4_worker_manager_api_lifecycle_and_public_status(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("SENTINELUEBA_DATA_DIR", str(tmp_path / "data"))
    monkeypatch.setenv("SENTINELUEBA_DATABASE_PATH", str(tmp_path / "data" / "api-worker.sqlite3"))
    monkeypatch.setenv("SENTINELUEBA_MODEL_DIR", str(tmp_path / "model"))
    client = TestClient(app)

    assert client.post("/demo/generate", json={"seed": 42}).status_code == 200
    materialized = client.post(
        "/features/materialize",
        json={"dataset_kind": "synthetic"},
    )
    assert materialized.status_code == 200
    started = client.post(
        "/detection/worker/start",
        json={"dataset_kind": "synthetic", "interval_seconds": 5},
    )
    assert started.status_code == 200

    storage = SQLiteStorage(tmp_path / "data" / "api-worker.sqlite3")
    for _ in range(80):
        with storage.connect() as conn:
            count = int(conn.execute("SELECT COUNT(*) FROM detection_evaluations").fetchone()[0])
        if count == 96:
            break
        time.sleep(0.1)
    assert count == 96

    status = client.get("/detection/worker/status").json()["data"]
    assert status["process_running"] is True
    assert status["worker_key"] == "stage4|synthetic|*"
    assert "owner_id" not in status
    assert "hostname" not in status
    assert "config_json" not in status
    assert "thread" not in status

    stopped = client.post("/detection/worker/stop", json={"confirm": True})
    assert stopped.status_code == 200
    final = client.get("/detection/worker/status").json()["data"]
    assert final["process_running"] is False
    assert final["status"] in {"stopped", "stopping"}


def test_stage4_worker_owner_rules_and_repeated_single_cycle(tmp_path: Path) -> None:
    pipe = prepared_pipe(tmp_path)
    service = pipe.detection()
    lease = service._acquire_worker_lease(
        dataset_kind="synthetic",
        interval_seconds=5,
        profile=None,
        lease_seconds=30,
        owner_id="owner-a",
    )
    with pytest.raises(DetectionEngineError, match="active detection worker lease"):
        service._acquire_worker_lease(
            dataset_kind="synthetic",
            interval_seconds=5,
            profile=None,
            lease_seconds=30,
            owner_id="owner-b",
        )
    service._worker_heartbeat(
        worker_id=str(lease["worker_id"]),
        owner_id="owner-b",
        interval_seconds=5,
        status="idle",
        safe_error=None,
    )
    with pipe.storage.connect() as conn:
        row = conn.execute(
            "SELECT owner_id, status FROM detection_worker_leases WHERE worker_key = ?",
            ("stage4|synthetic|*",),
        ).fetchone()
    assert row["owner_id"] == "owner-a"
    service._release_worker_lease(
        worker_id=str(lease["worker_id"]),
        owner_id="owner-a",
        status="stopped",
        safe_error=None,
    )

    first = pipe.detection_worker_run_foreground(
        dataset_kind="synthetic",
        max_windows=1,
        interval_seconds=5,
        single_cycle=True,
    )
    second = pipe.detection_worker_run_foreground(
        dataset_kind="synthetic",
        max_windows=1,
        interval_seconds=5,
        single_cycle=True,
    )
    assert first["worker"]["status"] == "stopped"
    assert second["worker"]["status"] == "stopped"


def test_stage4_registered_snapshot_backfill_exact_and_idempotent(tmp_path: Path) -> None:
    pipe = prepared_pipe(tmp_path)
    dataset = pipe.create_dataset("synthetic")
    dataset_id = str(dataset["dataset_id"])

    result = pipe.detection_backfill(
        policy_id=RULES_ONLY_POLICY_ID,
        registered_dataset_id=dataset_id,
        confirm=True,
    )
    assert result["evaluated_count"] == 96
    assert result["finding_count"] >= 5
    assert detection_table_counts(pipe.storage)["detection_watermarks"] == 0

    repeat = pipe.detection_backfill(
        policy_id=RULES_ONLY_POLICY_ID,
        registered_dataset_id=dataset_id,
        confirm=True,
    )
    assert repeat["examined_count"] == 0
    assert repeat["evaluated_count"] == 0


def test_stage4_registered_snapshot_backfill_ignores_extra_current_window(
    tmp_path: Path,
) -> None:
    pipe = prepared_pipe(tmp_path)
    dataset = pipe.create_dataset("synthetic")
    dataset_id = str(dataset["dataset_id"])
    extra = dict(pipe.storage.list_feature_windows(dataset_kind="synthetic")[0])
    extra["window_id"] = "extra-current-window"
    extra["window_start"] = (
        datetime.fromisoformat(str(extra["window_start"])) + timedelta(minutes=1)
    ).isoformat()
    extra["window_end"] = (
        datetime.fromisoformat(str(extra["window_end"])) + timedelta(minutes=1)
    ).isoformat()
    extra["source_event_hash"] = "extra-current-source"
    pipe.storage.upsert_feature_windows([extra])

    result = pipe.detection_backfill(
        policy_id=RULES_ONLY_POLICY_ID,
        registered_dataset_id=dataset_id,
        confirm=True,
    )

    assert result["examined_count"] == 96
    assert result["evaluated_count"] == 96
    with pipe.storage.connect() as conn:
        extra_eval = conn.execute(
            "SELECT COUNT(*) FROM detection_evaluations WHERE window_id = ?",
            ("extra-current-window",),
        ).fetchone()[0]
    assert extra_eval == 0


def test_stage4_registered_snapshot_backfill_rejects_current_revision(
    tmp_path: Path,
) -> None:
    pipe = prepared_pipe(tmp_path)
    dataset = pipe.create_dataset("synthetic")
    dataset_id = str(dataset["dataset_id"])
    window = pipe.storage.list_feature_windows(dataset_kind="synthetic")[0]
    features = dict(window["features"])
    features["process_count"] = float(features["process_count"]) + 1.0
    with pipe.storage.connect() as conn:
        conn.execute(
            "UPDATE feature_windows SET features_json = ? WHERE window_id = ?",
            (json.dumps(features, sort_keys=True), window["window_id"]),
        )

    with pytest.raises(DetectionEngineError, match="feature revision mismatch"):
        pipe.detection_backfill(
            policy_id=RULES_ONLY_POLICY_ID,
            registered_dataset_id=dataset_id,
            confirm=True,
        )
    with pipe.storage.connect() as conn:
        blocked = conn.execute(
            """
            SELECT status, run_mode, blocked_reason
            FROM detection_runs
            ORDER BY started_at DESC
            LIMIT 1
            """
        ).fetchone()
    assert blocked["status"] == "blocked"
    assert blocked["run_mode"] == "backfill"
    assert "feature revision mismatch" in blocked["blocked_reason"]


def test_stage4_model_strength_handles_threshold_edges() -> None:
    assert model_strength(0.0, 0.0) == 0
    assert model_strength(1.0, 0.0) == 100
    assert model_strength(2.0, 1.0) == 100
    assert model_strength(-0.5, -1.0) == 100
    with pytest.raises(DetectionEngineError):
        model_strength(float("nan"), 1.0)


def test_stage4_api_and_cli_smoke(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("SENTINELUEBA_DATA_DIR", str(tmp_path / "data"))
    monkeypatch.setenv("SENTINELUEBA_DATABASE_PATH", str(tmp_path / "data" / "api.sqlite3"))
    monkeypatch.setenv("SENTINELUEBA_MODEL_DIR", str(tmp_path / "model"))
    client = TestClient(app)

    assert client.post("/demo/generate", json={"seed": 42}).status_code == 200
    assert (
        client.post("/features/materialize", json={"dataset_kind": "synthetic"}).status_code
        == 200
    )
    response = client.post(
        "/detection/run-once",
        json={"dataset_kind": "synthetic", "rules_only": True},
    )
    assert response.status_code == 200
    assert response.json()["data"]["evaluated_count"] == 96
    assert client.get("/detection/status").json()["data"]["active_policy"]["policy_id"] == (
        DEFAULT_POLICY_ID
    )
    assert client.get("/detection/rules").status_code == 200
    assert client.get("/detection/findings").status_code == 200

    runner = CliRunner()
    assert runner.invoke(cli_app, ["detection", "status"]).exit_code == 0
    assert runner.invoke(cli_app, ["detection", "rules", "list"]).exit_code == 0
    assert runner.invoke(cli_app, ["detection", "runs", "list"]).exit_code == 0
