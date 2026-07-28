from __future__ import annotations

import json
import sqlite3
import threading
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
from sentinelueba.detection.contracts import DetectionInput, ModelSignal
from sentinelueba.detection.policies import DEFAULT_POLICY_ID, RULES_ONLY_POLICY_ID
from sentinelueba.detection.service import DetectionEngineError, DetectionService, model_strength
from sentinelueba.features.windows import FEATURE_NAMES, FEATURE_SCHEMA_VERSION
from sentinelueba.ml.stage3_models import AutoencoderV2Config
from sentinelueba.ml.stage3_service import ModelBundleVerifier
from sentinelueba.services.pipeline import DemoPipeline
from sentinelueba.storage.sqlite import DB_SCHEMA_VERSION, SchemaIntegrityError, SQLiteStorage
from test_stage2_data_pipeline import create_historical_database


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


def synthetic_window(
    index: int,
    *,
    window_id: str,
    source_hash: str,
) -> dict[str, object]:
    start = datetime.fromisoformat("2026-02-01T00:00:00+00:00") + timedelta(
        minutes=15 * index
    )
    features = {name: 0.0 for name in FEATURE_NAMES}
    features["hour_of_day"] = float(start.hour)
    return {
        "window_id": window_id,
        "dataset_kind": "synthetic",
        "user_id": "pending-user",
        "host_id": "pending-host",
        "window_start": start.isoformat(),
        "window_end": (start + timedelta(minutes=15)).isoformat(),
        "feature_schema_version": FEATURE_SCHEMA_VERSION,
        "window_size_minutes": 15,
        "features": features,
        "event_count": 1,
        "event_counts": {"process": 1},
        "collector_coverage": {"heartbeat_coverage": 1.0},
        "quality_status": "good",
        "quality_reasons": [],
        "gap_duration_seconds": 0.0,
        "finalized": True,
        "source_event_hash": source_hash,
    }


def register_fake_champion(
    storage: SQLiteStorage,
    *,
    model_id: str,
    profile: str,
) -> None:
    now = datetime.now().astimezone().isoformat()
    training_run_id = f"train-{model_id}"
    storage.create_training_run(
        {
            "training_run_id": training_run_id,
            "dataset_id": f"dataset-{model_id}",
            "dataset_manifest_sha256": "a" * 64,
            "dataset_kind": "synthetic",
            "profile_key": profile,
            "split_id": f"split-{model_id}",
            "split_manifest_sha256": "b" * 64,
            "effective_config_json": "{}",
            "config_sha256": "c" * 64,
            "seed": 42,
            "status": "success",
            "started_at": now,
            "completed_at": now,
            "application_version": "test",
        }
    )
    storage.register_model_version(
        {
            "model_id": model_id,
            "training_run_id": training_run_id,
            "family": "autoencoder",
            "model_version": f"v-{model_id}",
            "dataset_id": f"dataset-{model_id}",
            "dataset_manifest_sha256": "a" * 64,
            "dataset_kind": "synthetic",
            "profile_key": profile,
            "feature_schema_version": FEATURE_SCHEMA_VERSION,
            "split_id": f"split-{model_id}",
            "artifact_path": f"models/{model_id}",
            "manifest_sha256": "d" * 64,
            "model_artifact_sha256": "e" * 64,
            "lifecycle_status": "champion",
            "threshold": 0.5,
            "created_at": now,
            "verified_at": now,
        }
    )

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


def test_stage4_v8_stage3_model_rows_migrate_to_v10(tmp_path: Path) -> None:
    db = tmp_path / "v8-stage3.sqlite3"
    create_historical_database(db, 7)
    storage = SQLiteStorage(db)
    with storage.connect() as conn:
        storage._apply_v8(conn)
        conn.execute(
            """
            INSERT INTO training_runs (
                training_run_id, dataset_id, dataset_manifest_sha256, dataset_kind,
                profile_key, split_id, split_manifest_sha256, effective_config_json,
                config_sha256, seed, status, started_at, completed_at, application_version,
                source_commit, error_class, safe_error_message
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                "train-v8",
                "dataset-v8",
                "manifest-v8",
                "synthetic",
                "profile-v8",
                "split-v8",
                "split-manifest-v8",
                "{}",
                "config-v8",
                42,
                "success",
                "2026-01-01T00:00:00+00:00",
                "2026-01-01T00:01:00+00:00",
                "0.1.0",
                "source-v8",
                None,
                None,
            ),
        )
        conn.execute(
            """
            INSERT INTO model_versions (
                model_id, training_run_id, family, model_version, dataset_id,
                dataset_manifest_sha256, dataset_kind, profile_key, feature_schema_version,
                split_id, artifact_path, manifest_sha256, model_artifact_sha256,
                lifecycle_status, threshold, created_at, verified_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                "model-v8",
                "train-v8",
                "autoencoder",
                "autoencoder-v2",
                "dataset-v8",
                "manifest-v8",
                "synthetic",
                "profile-v8",
                FEATURE_SCHEMA_VERSION,
                "split-v8",
                "artifacts/model-v8",
                "bundle-v8",
                "artifact-v8",
                "champion",
                0.5,
                "2026-01-01T00:01:00+00:00",
                "2026-01-01T00:01:30+00:00",
            ),
        )

    storage.initialize()

    with sqlite3.connect(db) as conn:
        conn.row_factory = sqlite3.Row
        assert conn.execute("SELECT MAX(version) FROM schema_version").fetchone()[0] == 10
        model = conn.execute("SELECT * FROM model_versions WHERE model_id = 'model-v8'").fetchone()
        assert model is not None
        assert model["lifecycle_status"] == "champion"
        tables = {
            row["name"]
            for row in conn.execute("SELECT name FROM sqlite_master WHERE type = 'table'")
        }
        assert "detection_policies" in tables


def test_stage4_v9_detection_rows_migrate_to_v10(tmp_path: Path) -> None:
    db = tmp_path / "v9-stage4.sqlite3"
    create_historical_database(db, 7)
    storage = SQLiteStorage(db)
    now = "2026-01-01T00:00:00+00:00"
    window = synthetic_window(0, window_id="window-v9", source_hash="source-v9")
    with storage.connect() as conn:
        storage._apply_v8(conn)
        storage._apply_v9(conn)
        conn.execute(
            """
            INSERT INTO feature_windows (
                window_id, dataset_kind, user_id, host_id, window_start, window_end,
                feature_schema_version, window_size_minutes, features_json, event_count,
                event_counts_json, collector_coverage_json, quality_status,
                quality_reasons_json, gap_duration_seconds, finalized, source_event_hash,
                created_at, updated_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                window["window_id"],
                window["dataset_kind"],
                window["user_id"],
                window["host_id"],
                window["window_start"],
                window["window_end"],
                window["feature_schema_version"],
                window["window_size_minutes"],
                json.dumps(window["features"], sort_keys=True),
                window["event_count"],
                json.dumps(window["event_counts"], sort_keys=True),
                json.dumps(window["collector_coverage"], sort_keys=True),
                window["quality_status"],
                json.dumps(window["quality_reasons"], sort_keys=True),
                window["gap_duration_seconds"],
                1,
                window["source_event_hash"],
                now,
                now,
            ),
        )
        conn.execute(
            """
            INSERT INTO detection_runs (
                detection_run_id, dataset_kind, profile_key, policy_id, policy_version,
                policy_hash, mode, model_id, model_version, model_hash, status, started_at,
                completed_at, window_count, evaluated_count, skipped_count, finding_count,
                no_op_count, dry_run, safe_error
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                "detect-v9",
                "synthetic",
                "profile-v9",
                DEFAULT_POLICY_ID,
                "2026-01-01",
                "policy-v9",
                "hybrid",
                "model-v9",
                "v9",
                "model-hash-v9",
                "success",
                now,
                now,
                1,
                1,
                0,
                1,
                0,
                0,
                None,
            ),
        )
        conn.execute(
            """
            INSERT INTO detection_evaluations (
                evaluation_id, detection_run_id, window_id, dataset_kind, profile_key,
                window_start, window_end, feature_schema_version, feature_input_hash,
                policy_id, policy_version, policy_hash, model_id, model_version, model_hash,
                mode, status, detection_score, risk_level, matched_signal_ids_json,
                decision_json, finding_id, created_at, skipped_reason
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                "eval-v9",
                "detect-v9",
                "window-v9",
                "synthetic",
                "profile-v9",
                window["window_start"],
                window["window_end"],
                FEATURE_SCHEMA_VERSION,
                "feature-hash-v9",
                DEFAULT_POLICY_ID,
                "2026-01-01",
                "policy-v9",
                "model-v9",
                "v9",
                "model-hash-v9",
                "hybrid",
                "finding",
                80.0,
                "high",
                json.dumps(["rare-process-v1"]),
                json.dumps({"matched": True}),
                "finding-v9",
                now,
                None,
            ),
        )
        conn.execute(
            """
            INSERT INTO findings (
                finding_id, fingerprint, dataset_kind, profile_key, policy_id,
                policy_version, policy_hash, model_id, model_version, model_hash, status,
                risk_level, detection_score, primary_signal_id, title, summary,
                first_seen_at, last_seen_at, occurrence_count, created_at, updated_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                "finding-v9",
                "fingerprint-v9",
                "synthetic",
                "profile-v9",
                DEFAULT_POLICY_ID,
                "2026-01-01",
                "policy-v9",
                "model-v9",
                "v9",
                "model-hash-v9",
                "open",
                "high",
                80.0,
                "rare-process-v1",
                "Finding v9",
                "Finding summary v9",
                now,
                now,
                1,
                now,
                now,
            ),
        )
        conn.execute(
            """
            INSERT INTO detection_worker_leases (
                worker_id, owner_id, status, heartbeat_at, stop_requested,
                config_json, safe_error
            ) VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            ("worker-v9", "owner-v9", "idle", now, 0, "{}", None),
        )

    storage.initialize()

    with sqlite3.connect(db) as conn:
        conn.row_factory = sqlite3.Row
        assert conn.execute("SELECT MAX(version) FROM schema_version").fetchone()[0] == 10
        feature_columns = {
            row["name"] for row in conn.execute("PRAGMA table_info(feature_windows)")
        }
        assert {"profile_key", "feature_input_hash"}.issubset(feature_columns)
        run = conn.execute(
            "SELECT * FROM detection_runs WHERE detection_run_id = 'detect-v9'"
        ).fetchone()
        assert run is not None
        assert run["run_mode"] == "manual"
        assert run["policy_mode"] == "hybrid"
        evaluation = conn.execute(
            "SELECT * FROM detection_evaluations WHERE evaluation_id = 'eval-v9'"
        ).fetchone()
        assert evaluation is not None
        assert "suppression_id" in dict(evaluation)
        worker = conn.execute(
            "SELECT * FROM detection_worker_leases WHERE worker_id = 'worker-v9'"
        ).fetchone()
        assert worker is not None
        assert "worker_key" in dict(worker)


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


def test_stage4_multi_profile_routes_each_champion_without_cross_profile_fallback(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    pipe = DemoPipeline(settings(tmp_path))
    pipe.initialize()
    pipe.storage.upsert_feature_windows(
        [
            synthetic_window(0, window_id="profile-a-window", source_hash="profile-a-source")
            | {"user_id": "profile-a-user", "host_id": "profile-a-host"},
            synthetic_window(1, window_id="profile-b-window", source_hash="profile-b-source")
            | {"user_id": "profile-b-user", "host_id": "profile-b-host"},
        ]
    )
    profiles = pipe.storage.list_detection_profiles(dataset_kind="synthetic")
    assert len(profiles) == 2
    profile_a, profile_b = profiles
    register_fake_champion(pipe.storage, model_id="model-a", profile=profile_a)
    register_fake_champion(pipe.storage, model_id="model-b", profile=profile_b)

    class Preprocessor:
        feature_names = FEATURE_NAMES

    class Artifact:
        input_dimension = len(FEATURE_NAMES)

    monkeypatch.setattr(
        ModelBundleVerifier,
        "verify",
        lambda self, model_id: {"model_id": model_id, "verified": True},
    )
    monkeypatch.setattr(
        ModelBundleVerifier,
        "load",
        lambda self, model_id: ({}, Preprocessor(), Artifact()),
    )
    scored: list[tuple[str, str]] = []

    def model_signal(
        self: DetectionService,
        detection_input: DetectionInput,
        model_record: dict[str, object] | None,
        model_context: dict[str, object] | None,
    ) -> ModelSignal:
        del self, model_context
        assert model_record is not None
        scored.append((detection_input.profile_key, str(model_record["model_id"])))
        return ModelSignal(
            signal_id=f"model-{model_record['model_id']}",
            signal_version="test",
            strength=90,
            matched=True,
            summary="test model signal",
            evidence=(),
            contributing_feature_names=(),
            config_hash="model-test",
            model_id=str(model_record["model_id"]),
            model_version=str(model_record["model_version"]),
            model_hash=str(model_record["model_artifact_sha256"]),
            anomaly_score=1.0,
            threshold=0.5,
        )

    monkeypatch.setattr(DetectionService, "_model_signal", model_signal)
    result = pipe.detection_run_once(dataset_kind="synthetic", rules_only=False)

    assert len(result["child_run_ids"]) == 2
    assert set(scored) == {(profile_a, "model-a"), (profile_b, "model-b")}
    assert pipe.detection_run(str(result["child_run_ids"][0])) is not None
    mismatched = pipe.detection_run_once(
        dataset_kind="synthetic",
        profile=f"{profile_b}-other",
        model_id="model-a",
    )
    assert mismatched["status"] == "blocked"
    assert "model profile does not match" in str(mismatched["safe_error"])

    isolated = DemoPipeline(settings(tmp_path / "no-b-champion"))
    isolated.initialize()
    isolated.storage.upsert_feature_windows(
        [
            synthetic_window(0, window_id="profile-a-window", source_hash="profile-a-source")
            | {"user_id": "profile-a-user", "host_id": "profile-a-host"},
            synthetic_window(1, window_id="profile-b-window", source_hash="profile-b-source")
            | {"user_id": "profile-b-user", "host_id": "profile-b-host"},
        ]
    )
    profile_a2, profile_b2 = isolated.storage.list_detection_profiles(dataset_kind="synthetic")
    register_fake_champion(isolated.storage, model_id="model-a", profile=profile_a2)
    degraded = isolated.detection_run_once(dataset_kind="synthetic", profile=profile_b2)
    assert degraded["model_id"] is None
    assert degraded["policy_id"] == RULES_ONLY_POLICY_ID
    assert degraded["policy_hash"] == isolated.detection_policy(RULES_ONLY_POLICY_ID)[
        "policy_hash"
    ]


def test_stage4_policy_registry_and_rule_config_tampering_is_rejected(
    tmp_path: Path,
) -> None:
    pipe = prepared_pipe(tmp_path)
    pipe.detection_policies()
    with pipe.storage.connect() as conn:
        row = conn.execute(
            "SELECT * FROM detection_policies WHERE policy_id = ?",
            (DEFAULT_POLICY_ID,),
        ).fetchone()
    policy_json = json.loads(row["policy_json"])

    with pipe.storage.connect() as conn:
        tampered = dict(policy_json)
        tampered["finding_threshold"] = int(tampered["finding_threshold"]) + 1
        conn.execute(
            "UPDATE detection_policies SET policy_json = ? WHERE policy_hash = ?",
            (json.dumps(tampered, sort_keys=True), row["policy_hash"]),
        )
    with pytest.raises(DetectionEngineError):
        pipe.detection_policy(DEFAULT_POLICY_ID)

    pipe = prepared_pipe(tmp_path / "registry-column")
    pipe.detection_policies()
    with pipe.storage.connect() as conn:
        conn.execute(
            "UPDATE detection_policies SET mode = 'rules_only' WHERE policy_id = ?",
            (DEFAULT_POLICY_ID,),
        )
    with pytest.raises(DetectionEngineError):
        pipe.detection_policy(DEFAULT_POLICY_ID)

    pipe = prepared_pipe(tmp_path / "unknown-rule")
    pipe.detection_policies()
    with pipe.storage.connect() as conn:
        row = conn.execute(
            "SELECT * FROM detection_policies WHERE policy_id = ?",
            (DEFAULT_POLICY_ID,),
        ).fetchone()
        payload = json.loads(row["policy_json"])
        payload["rules"][0]["rule_id"] = "unknown-rule-v1"
        conn.execute(
            "UPDATE detection_policies SET policy_json = ? WHERE policy_hash = ?",
            (json.dumps(payload, sort_keys=True), row["policy_hash"]),
        )
    with pytest.raises(DetectionEngineError):
        pipe.detection_policy(DEFAULT_POLICY_ID)

    pipe = prepared_pipe(tmp_path / "extra-config")
    pipe.detection_policies()
    with pipe.storage.connect() as conn:
        row = conn.execute(
            "SELECT * FROM detection_policies WHERE policy_id = ?",
            (DEFAULT_POLICY_ID,),
        ).fetchone()
        payload = json.loads(row["policy_json"])
        payload["rules"][0]["config"]["unexpected"] = 1
        conn.execute(
            "UPDATE detection_policies SET policy_json = ? WHERE policy_hash = ?",
            (json.dumps(payload, sort_keys=True), row["policy_hash"]),
        )
    with pytest.raises(DetectionEngineError):
        pipe.detection_policy(DEFAULT_POLICY_ID)


def test_stage4_idempotency_makes_second_same_run_noop(tmp_path: Path) -> None:
    pipe = prepared_pipe(tmp_path)
    first = pipe.detection_run_once(dataset_kind="synthetic", rules_only=True)
    second = pipe.detection_run_once(dataset_kind="synthetic", rules_only=True)

    assert first["evaluated_count"] == 96
    assert second["evaluated_count"] == 0
    assert second["examined_count"] == 0
    assert second["child_run_ids"] == [run_id(second)]
    assert pipe.detection_status()["active_policy"]["policy_id"] == DEFAULT_POLICY_ID


def test_stage4_pending_query_reaches_new_tail_and_historical_revision(
    tmp_path: Path,
) -> None:
    pipe = DemoPipeline(settings(tmp_path))
    pipe.initialize()
    pipe.detection_policy(RULES_ONLY_POLICY_ID)
    windows = [
        synthetic_window(i, window_id=f"pending-{i:04d}", source_hash=f"source-{i:04d}")
        for i in range(1010)
    ]
    pipe.storage.upsert_feature_windows(windows)
    profile = pipe.storage.list_detection_profiles(dataset_kind="synthetic")[0]
    policy = pipe.detection_policy(RULES_ONLY_POLICY_ID)
    now = datetime.now().astimezone().isoformat()
    stored_windows = pipe.storage.list_feature_windows(dataset_kind="synthetic")
    old_windows = stored_windows[:1000]
    with pipe.storage.connect() as conn:
        conn.executemany(
            """
            INSERT INTO detection_evaluations (
                evaluation_id, detection_run_id, window_id, dataset_kind, profile_key,
                window_start, window_end, feature_schema_version, feature_input_hash,
                policy_id, policy_version, policy_hash, model_id, model_version,
                model_hash, mode, status, detection_score, risk_level,
                matched_signal_ids_json, decision_json, finding_id, created_at,
                skipped_reason, suppression_id, suppression_reason, suppression_expires_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, NULL, NULL, ?, ?, 0, 'none',
                '[]', '{}', NULL, ?, NULL, NULL, NULL, NULL)
            """,
            [
                (
                    f"seed-eval-{index}",
                    "seed-run",
                    window["window_id"],
                    "synthetic",
                    profile,
                    window["window_start"],
                    window["window_end"],
                    window["feature_schema_version"],
                    window["feature_input_hash"],
                    RULES_ONLY_POLICY_ID,
                    policy["policy_version"],
                    policy["policy_hash"],
                    "__rules_only__",
                    "rules_only",
                    "no_finding",
                    now,
                )
                for index, window in enumerate(old_windows)
            ],
        )

    result = pipe.detection_run_once(
        dataset_kind="synthetic",
        profile=profile,
        rules_only=True,
        max_windows=16,
    )
    assert result["examined_count"] == 10
    assert result["evaluated_count"] == 10
    repeat = pipe.detection_run_once(
        dataset_kind="synthetic",
        profile=profile,
        rules_only=True,
        max_windows=16,
    )
    assert repeat["examined_count"] == 0
    assert repeat["evaluated_count"] == 0

    revised = synthetic_window(0, window_id="pending-0000", source_hash="source-revised")
    revised_features = dict(revised["features"])  # type: ignore[index]
    revised_features["process_count"] = 2.0
    revised["features"] = revised_features
    pipe.storage.upsert_feature_windows([revised])
    historical = pipe.detection_run_once(
        dataset_kind="synthetic",
        profile=profile,
        rules_only=True,
        max_windows=16,
    )
    assert historical["examined_count"] == 1
    assert historical["evaluated_count"] == 1


def test_stage4_concurrent_same_namespace_rejects_second_run_without_duplicates(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    pipe = prepared_pipe(tmp_path)
    profile = pipe.storage.list_detection_profiles(dataset_kind="synthetic")[0]
    service_a = pipe.detection()
    service_b = pipe.detection()
    original = DetectionService._evaluate_window_atomic
    first_window_started = threading.Event()

    def slow_evaluate(self: DetectionService, **kwargs: object) -> dict[str, object]:
        if not first_window_started.is_set():
            first_window_started.set()
            time.sleep(0.4)
        return original(self, **kwargs)  # type: ignore[arg-type]

    monkeypatch.setattr(DetectionService, "_evaluate_window_atomic", slow_evaluate)
    results: list[dict[str, object]] = []
    errors: list[Exception] = []

    def run(service: DetectionService) -> None:
        try:
            results.append(
                service.run_once(
                    dataset_kind="synthetic",
                    profile=profile,
                    rules_only=True,
                )
            )
        except Exception as exc:  # noqa: BLE001
            errors.append(exc)

    thread_a = threading.Thread(target=run, args=(service_a,))
    thread_b = threading.Thread(target=run, args=(service_b,))
    thread_a.start()
    assert first_window_started.wait(timeout=2.0)
    thread_b.start()
    thread_a.join(timeout=5.0)
    thread_b.join(timeout=5.0)

    assert len(results) == 1
    assert results[0]["evaluated_count"] == 96
    assert len(errors) == 1
    assert "active running lease" in str(errors[0])
    with pipe.storage.connect() as conn:
        duplicate_eval = conn.execute(
            """
            SELECT COUNT(*)
            FROM (
                SELECT window_id, feature_input_hash, policy_hash, model_id
                FROM detection_evaluations
                GROUP BY window_id, feature_input_hash, policy_hash, model_id
                HAVING COUNT(*) > 1
            )
            """
        ).fetchone()[0]
        orphan_occurrence = conn.execute(
            """
            SELECT COUNT(*)
            FROM finding_occurrences o
            LEFT JOIN detection_evaluations e ON e.evaluation_id = o.evaluation_id
            WHERE e.evaluation_id IS NULL
            """
        ).fetchone()[0]
        occurrence_count = conn.execute(
            "SELECT COALESCE(SUM(occurrence_count), 0) FROM findings"
        ).fetchone()[0]
        stored_occurrences = conn.execute(
            "SELECT COUNT(*) FROM finding_occurrences"
        ).fetchone()[0]
    assert duplicate_eval == 0
    assert orphan_occurrence == 0
    assert occurrence_count == stored_occurrences


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


def test_stage4_dry_run_surfaces_model_and_policy_failures(tmp_path: Path) -> None:
    pipe = prepared_pipe(tmp_path)
    trained = pipe.ml().train(
        dataset_kind="synthetic",
        families=["autoencoder"],
        autoencoder_config=asdict(AutoencoderV2Config(epochs=6, plateau_patience=4)),
    )
    model_id = str(trained["candidates"][0]["model_id"])
    profile = str(pipe.storage.get_model_version(model_id)["profile_key"])  # type: ignore[index]
    blocked = pipe.detection_run_once(
        dataset_kind="synthetic",
        profile=f"{profile}-other",
        model_id=model_id,
        dry_run=True,
    )
    assert blocked["status"] == "blocked"
    assert blocked["dry_run"] is True
    assert blocked["examined_count"] == 0
    assert "model profile does not match" in str(blocked["safe_error"])

    with pipe.storage.connect() as conn:
        conn.execute("UPDATE model_versions SET verified_at = NULL WHERE model_id = ?", (model_id,))
        conn.execute(
            "UPDATE training_runs SET status = 'running', completed_at = NULL "
            "WHERE training_run_id = ?",
            (trained["training_run_id"],),
        )
    pending = pipe.detection_run_once(
        dataset_kind="synthetic",
        model_id=model_id,
        dry_run=True,
    )
    assert pending["status"] == "blocked"
    assert "not finalized" in str(pending["safe_error"])

    with pipe.storage.connect() as conn:
        conn.execute(
            "UPDATE training_runs SET status = 'failed', completed_at = NULL "
            "WHERE training_run_id = ?",
            (trained["training_run_id"],),
        )
    failed = pipe.detection_run_once(
        dataset_kind="synthetic",
        model_id=model_id,
        dry_run=True,
    )
    assert failed["status"] == "blocked"
    assert "not finalized" in str(failed["safe_error"])

    with pytest.raises(DetectionEngineError):
        pipe.detection_run_once(dataset_kind="synthetic", model_id="missing-model", dry_run=True)

    pipe = prepared_pipe(tmp_path / "damaged-policy")
    pipe.detection_policies()
    with pipe.storage.connect() as conn:
        conn.execute(
            "UPDATE detection_policies SET policy_json = ? WHERE policy_id = ?",
            ('{"policy_id":"hybrid-policy-v1"}', DEFAULT_POLICY_ID),
        )
    with pytest.raises(DetectionEngineError):
        pipe.detection_run_once(
            dataset_kind="synthetic",
            policy_id=DEFAULT_POLICY_ID,
            dry_run=True,
        )


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
        worker_key="stage4|synthetic|*",
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
        worker_key="stage4|synthetic|*",
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


def test_stage4_worker_status_and_stop_are_worker_key_scoped(tmp_path: Path) -> None:
    pipe = prepared_pipe(tmp_path)
    service = pipe.detection()
    synthetic = service._acquire_worker_lease(
        dataset_kind="synthetic",
        interval_seconds=5,
        profile=None,
        lease_seconds=30,
        owner_id="owner-synthetic",
    )
    real = service._acquire_worker_lease(
        dataset_kind="real",
        interval_seconds=5,
        profile=None,
        lease_seconds=30,
        owner_id="owner-real",
    )

    assert service.worker_status(dataset_kind="synthetic")["worker_key"] == (
        "stage4|synthetic|*"
    )
    assert service.worker_status(dataset_kind="real")["worker_key"] == "stage4|real|*"
    stopped = service.worker_stop(dataset_kind="synthetic", confirm=True)
    assert stopped["worker_key"] == "stage4|synthetic|*"
    assert stopped["stop_requested"] is True
    real_status = service.worker_status(dataset_kind="real")
    assert real_status["worker_key"] == "stage4|real|*"
    assert real_status["stop_requested"] is False

    service._release_worker_lease(
        worker_id=str(synthetic["worker_id"]),
        owner_id="owner-synthetic",
        worker_key="stage4|synthetic|*",
        status="stopped",
        safe_error=None,
    )
    service._release_worker_lease(
        worker_id=str(real["worker_id"]),
        owner_id="owner-real",
        worker_key="stage4|real|*",
        status="stopped",
        safe_error=None,
    )


def test_stage4_worker_start_conflict_before_thread_and_long_run_heartbeat(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    pipe = prepared_pipe(tmp_path)
    service = pipe.detection()
    lease = service._acquire_worker_lease(
        dataset_kind="synthetic",
        interval_seconds=5,
        profile=None,
        lease_seconds=5,
        owner_id="owner-long",
    )
    initial_expires = str(lease["expires_at"])
    started = threading.Event()

    def slow_run_once(**_: object) -> dict[str, object]:
        started.set()
        time.sleep(6.0)
        return {
            "status": "success",
            "evaluated_count": 0,
            "examined_count": 0,
            "finding_occurrences": 0,
            "new_findings": 0,
        }

    monkeypatch.setattr(service, "run_once", slow_run_once)
    thread = threading.Thread(
        target=service.worker_run_foreground,
        kwargs={
            "dataset_kind": "synthetic",
            "interval_seconds": 5,
            "single_cycle": True,
            "lease": lease,
        },
    )
    thread.start()
    assert started.wait(timeout=2.0)
    time.sleep(5.5)
    with pipe.storage.connect() as conn:
        row = conn.execute(
            "SELECT expires_at FROM detection_worker_leases WHERE worker_key = ?",
            ("stage4|synthetic|*",),
        ).fetchone()
    assert str(row["expires_at"]) > initial_expires
    with pytest.raises(DetectionEngineError, match="active detection worker lease"):
        service._acquire_worker_lease(
            dataset_kind="synthetic",
            interval_seconds=5,
            profile=None,
            lease_seconds=30,
            owner_id="owner-conflict",
        )
    thread.join(timeout=4.0)
    assert not thread.is_alive()
    assert service.worker_status(dataset_kind="synthetic")["status"] == "stopped"
    assert pipe.detection_worker_run_foreground(
        dataset_kind="synthetic",
        interval_seconds=5,
        max_windows=1,
        single_cycle=True,
    )["worker"]["status"] == "stopped"


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
