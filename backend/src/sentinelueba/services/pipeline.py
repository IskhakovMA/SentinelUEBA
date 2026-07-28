from __future__ import annotations

import shutil
import threading
from collections.abc import Callable
from datetime import datetime
from pathlib import Path

from sentinelueba.collectors.manager import (
    CollectionAlreadyRunningError,
    CollectionStopTimeoutError,
    NoAvailableCollectorsError,
    get_manager,
)
from sentinelueba.config import Settings
from sentinelueba.datasets import DatasetSnapshotService
from sentinelueba.detection.engine import summarize_scores
from sentinelueba.detection.service import DetectionService
from sentinelueba.detection.worker_manager import get_detection_worker_manager
from sentinelueba.domain.events import WindowFeatures
from sentinelueba.features.materialization import FeatureMaterializer
from sentinelueba.features.windows import FEATURE_NAMES
from sentinelueba.ml.autoencoder import model_info
from sentinelueba.ml.stage3_service import Stage3MLService
from sentinelueba.quality import DataQualityService, RetentionService
from sentinelueba.services.eligibility import EligibilityService
from sentinelueba.storage.sqlite import SQLiteStorage
from sentinelueba.telemetry.synthetic import generate_synthetic_events, scenario_manifest_for_start

_FEATURE_LOCKS = {"synthetic": threading.Lock(), "real": threading.Lock()}


class DemoPipeline:
    def __init__(self, settings: Settings) -> None:
        self.settings = settings
        self.settings.ensure_dirs()
        self.storage = SQLiteStorage(settings.database_path)

    def model_dir(self, dataset_kind: str = "synthetic") -> Path:
        return self.settings.model_dir / dataset_kind

    def snapshots(self) -> DatasetSnapshotService:
        return DatasetSnapshotService(self.storage, self.settings.data_dir)

    def ml(self) -> Stage3MLService:
        return Stage3MLService(self.storage, self.settings.data_dir, self.settings.model_dir)

    def detection(self) -> DetectionService:
        return DetectionService(self.storage, self.settings.data_dir, self.settings.model_dir)

    def materializer(self) -> FeatureMaterializer:
        return FeatureMaterializer(self.storage)

    def initialize(self) -> dict[str, object]:
        self.storage.initialize()
        return self.status()

    def generate_demo_data(self, seed: int = 42) -> dict[str, object]:
        self.storage.initialize()
        events, summary = generate_synthetic_events(seed=seed)
        inserted = self.storage.insert_events(events)
        return {
            "seed": summary.seed,
            "generated_events": summary.events,
            "inserted_events": inserted,
            "start": summary.start.isoformat(),
            "end": summary.end.isoformat(),
            "anomaly_scenarios": summary.anomaly_scenarios,
            "scenario_manifest": summary.scenario_manifest,
        }

    def train(self, seed: int = 42, dataset_kind: str = "synthetic") -> dict[str, object]:
        self.storage.initialize()
        result = self._with_feature_lock(
            dataset_kind,
            lambda: self._train_from_latest_materialization(dataset_kind, seed),
        )
        recommended = result.get("recommended_model_id")
        champion = self.storage.champion_model(dataset_kind)
        threshold = None
        if champion is not None:
            threshold = champion["threshold"]
        elif recommended is not None:
            recommended_record = self.storage.get_model_version(str(recommended))
            threshold = recommended_record["threshold"] if recommended_record else None
        return {
            "trained": True,
            "dataset_kind": dataset_kind,
            "training_run_id": result["training_run_id"],
            "dataset_id": result["dataset_id"],
            "dataset_manifest_sha256": result["dataset_manifest_sha256"],
            "split": result["split"],
            "candidates": result["candidates"],
            "recommended_model_id": recommended,
            "champion_model_id": champion["model_id"] if champion else None,
            "threshold": threshold,
        }

    def detect(self, dataset_kind: str = "synthetic") -> dict[str, object]:
        self.storage.initialize()
        champion = self.storage.champion_model(dataset_kind)
        if champion is None:
            raise ValueError("verified champion model is not available; retrain with Stage 3")
        result = self.ml().score(
            dataset_id=str(champion["dataset_id"]),
            model_id=str(champion["model_id"]),
            sync_anomalies=True,
        )
        anomalies = self.storage.list_anomalies()
        anomaly_payload = [item.model_dump(mode="json") for item in anomalies]
        latest_evaluation = self.storage.latest_model_evaluation(str(champion["model_id"])) or {}
        metrics = latest_evaluation.get("metrics", {}) if latest_evaluation else {}
        scenario_validation = []
        if dataset_kind == "synthetic":
            scoring_run = self.storage.get_scoring_run(str(result["scoring_run_id"])) or {}
            windows = scoring_run.get("windows", [])
            flagged_by_start = {
                str(window["window_start"]): window
                for window in windows
                if bool(window.get("is_anomaly"))
            }
            model_record = self.storage.get_model_version(str(champion["model_id"]))
            snapshot = (
                self.storage.get_dataset_snapshot(str(model_record["dataset_id"]))
                if model_record is not None
                else None
            )
            if snapshot is not None:
                scenario_validation = [
                    {
                        "scenario_name": item["name"],
                        "window_start": item["window_start"],
                        "detected": item["window_start"] in flagged_by_start,
                        "best_anomaly_score": float(
                            flagged_by_start.get(item["window_start"], {}).get(
                                "anomaly_score",
                                0.0,
                            )
                        ),
                    }
                    for item in scenario_manifest_for_start(
                        datetime.fromisoformat(str(snapshot["start"]))
                    )
                ]
        return {
            "windows": result["window_count"],
            "evaluation_windows": result["window_count"],
            "anomalies": len(anomalies),
            "summary": summarize_scores(anomalies),
            "top_anomalies": anomaly_payload[:5],
            "scenario_validation": scenario_validation,
            "scoring_run_id": result["scoring_run_id"],
            "model_id": champion["model_id"],
            "metrics": metrics,
        }

    def status(self) -> dict[str, object]:
        self.storage.initialize()
        storage_status = self.storage.status()
        info = model_info(self.model_dir("synthetic"))
        ml_status = self.ml().status()
        return {
            "project": "SentinelUEBA",
            "stage": "Stage 4",
            "windows_only": True,
            "storage": storage_status,
            "model": info,
            "ml": ml_status,
            "collection": self.collection_status(),
            "data_pipeline": {
                "features": self.materializer().status(),
                "snapshots": {
                    "synthetic": self.storage.list_dataset_snapshots("synthetic")[:1],
                    "real": self.storage.list_dataset_snapshots("real")[:1],
                },
                "quarantine": self.storage.quarantine_summary(),
            },
            "detection": self.detection().status(),
        }

    def anomalies(self) -> list[dict[str, object]]:
        self.storage.initialize()
        return [item.model_dump(mode="json") for item in self.storage.list_anomalies()]

    def summary(self) -> dict[str, object]:
        self.storage.initialize()
        return summarize_scores(self.storage.list_anomalies())

    def clean(self) -> dict[str, object]:
        self.storage.initialize()
        self.storage.clear_demo_data()
        if self.settings.model_dir.exists():
            shutil.rmtree(self.settings.model_dir)
            Path(self.settings.model_dir).mkdir(parents=True, exist_ok=True)
        stage3_models_dir = self.settings.model_dir.parent / "models"
        if stage3_models_dir.exists():
            shutil.rmtree(stage3_models_dir)
        return self.status()

    def collector_capabilities(self) -> list[dict[str, object]]:
        return get_manager(self.settings).capabilities()

    def start_collection(
        self,
        duration_seconds: int | None = None,
        interval_seconds: float = 5.0,
    ) -> dict[str, object]:
        try:
            return get_manager(self.settings).start(
                duration_seconds=duration_seconds,
                interval_seconds=interval_seconds,
            )
        except CollectionAlreadyRunningError as exc:
            raise ValueError(str(exc)) from exc
        except NoAvailableCollectorsError as exc:
            raise ValueError(
                f"{exc}; capabilities={exc.capabilities}"
            ) from exc

    def stop_collection(self) -> dict[str, object]:
        try:
            return get_manager(self.settings).stop()
        except CollectionStopTimeoutError as exc:
            raise ValueError(str(exc)) from exc

    def collection_status(self) -> dict[str, object]:
        manager = get_manager(self.settings)
        status = manager.status()
        status["event_summary"] = self.storage.event_summary()
        return status

    def collection_sessions(self) -> list[dict[str, object]]:
        self.storage.initialize()
        return self.storage.list_sessions()

    def collection_progress(self) -> dict[str, object]:
        self.storage.initialize()
        return self.storage.collection_progress()

    def event_summary(self) -> dict[str, object]:
        self.storage.initialize()
        return self.storage.event_summary()

    def training_eligibility(self, dataset_kind: str = "real") -> dict[str, object]:
        self.storage.initialize()
        return EligibilityService(self.storage).training_eligibility(dataset_kind)

    def data_quality(self) -> dict[str, object]:
        self.storage.initialize()
        return DataQualityService(self.storage).summary()

    def materialize_features(self, dataset_kind: str = "synthetic") -> dict[str, object]:
        self.storage.initialize()
        return self._with_feature_lock(
            dataset_kind,
            lambda: self.materializer().materialize(dataset_kind),
        )

    def rebuild_features(self, dataset_kind: str = "synthetic") -> dict[str, object]:
        self.storage.initialize()
        return self._with_feature_lock(
            dataset_kind,
            lambda: self.materializer().materialize(dataset_kind, rebuild=True),
        )

    def features_status(self) -> dict[str, object]:
        self.storage.initialize()
        return self.materializer().status()

    def create_dataset(self, dataset_kind: str = "synthetic") -> dict[str, object]:
        self.storage.initialize()
        return self._with_feature_lock(
            dataset_kind,
            lambda: self._create_dataset_locked(dataset_kind),
        )

    def list_datasets(self, dataset_kind: str | None = None) -> dict[str, object]:
        self.storage.initialize()
        return {"datasets": self.snapshots().list_snapshots(dataset_kind)}

    def show_dataset(self, dataset_id: str) -> dict[str, object]:
        self.storage.initialize()
        return self.snapshots().show(dataset_id)

    def verify_dataset(self, dataset_id: str) -> dict[str, object]:
        self.storage.initialize()
        return self.snapshots().verify(dataset_id)

    def retention_preview(self) -> dict[str, object]:
        self.storage.initialize()
        return RetentionService(self.storage).preview()

    def retention_apply(self) -> dict[str, object]:
        self.storage.initialize()
        return RetentionService(self.storage).apply()

    def quarantine_summary(self) -> dict[str, object]:
        self.storage.initialize()
        return self.storage.quarantine_summary()

    def ml_status(self) -> dict[str, object]:
        self.storage.initialize()
        return self.ml().status()

    def ml_train(
        self,
        *,
        dataset_kind: str = "synthetic",
        dataset_id: str | None = None,
        families: list[str] | None = None,
        seed: int = 42,
        target_fpr: float = 0.05,
        autoencoder_config: dict[str, object] | None = None,
        isolation_forest_config: dict[str, object] | None = None,
    ) -> dict[str, object]:
        self.storage.initialize()
        return self._with_feature_lock(
            dataset_kind,
            lambda: self._ml_train_locked(
                dataset_kind=dataset_kind,
                dataset_id=dataset_id,
                families=families,
                seed=seed,
                target_fpr=target_fpr,
                autoencoder_config=autoencoder_config,
                isolation_forest_config=isolation_forest_config,
            ),
        )

    def ml_models(self) -> list[dict[str, object]]:
        self.storage.initialize()
        return self.ml().list_models()

    def ml_model(self, model_id: str) -> dict[str, object]:
        self.storage.initialize()
        return self.ml().show_model(model_id)

    def ml_verify_model(self, model_id: str) -> dict[str, object]:
        self.storage.initialize()
        return self.ml().verify_model(model_id)

    def ml_recommend_model(
        self,
        model_id: str,
        *,
        confirm: bool,
        reason: str = "manual recommendation",
    ) -> dict[str, object]:
        self.storage.initialize()
        return self.ml().recommend(model_id, confirm=confirm, reason=reason)

    def ml_promote_model(
        self,
        model_id: str,
        *,
        confirm: bool,
        reason: str = "manual promotion",
    ) -> dict[str, object]:
        self.storage.initialize()
        return self.ml().promote(model_id, confirm=confirm, reason=reason)

    def ml_retire_model(
        self,
        model_id: str,
        *,
        confirm: bool,
        reason: str = "manual retirement",
    ) -> dict[str, object]:
        self.storage.initialize()
        return self.ml().retire(model_id, confirm=confirm, reason=reason)

    def ml_rollback_model(
        self,
        model_id: str,
        *,
        confirm: bool,
        reason: str = "manual rollback",
    ) -> dict[str, object]:
        self.storage.initialize()
        return self.ml().rollback(model_id, confirm=confirm, reason=reason)

    def ml_compare_models(self, model_ids: list[str]) -> dict[str, object]:
        self.storage.initialize()
        return self.ml().compare(model_ids)

    def ml_evaluate_model(self, model_id: str) -> dict[str, object]:
        self.storage.initialize()
        return self.ml().evaluate(model_id)

    def ml_score(
        self,
        *,
        dataset_id: str,
        model_id: str | None = None,
        dataset_kind: str | None = None,
        batch_size: int = 256,
    ) -> dict[str, object]:
        self.storage.initialize()
        return self.ml().score(
            dataset_id=dataset_id,
            model_id=model_id,
            dataset_kind=dataset_kind,
            batch_size=batch_size,
        )

    def ml_scoring_runs(self) -> list[dict[str, object]]:
        self.storage.initialize()
        return self.storage.list_scoring_runs()

    def ml_scoring_run(self, scoring_run_id: str) -> dict[str, object] | None:
        self.storage.initialize()
        return self.storage.get_scoring_run(scoring_run_id)

    def ml_training_runs(self) -> list[dict[str, object]]:
        self.storage.initialize()
        return self.storage.list_training_runs()

    def ml_training_run(self, training_run_id: str) -> dict[str, object] | None:
        self.storage.initialize()
        return self.storage.get_training_run(training_run_id)

    def ml_drift(self, *, model_id: str, dataset_id: str) -> dict[str, object]:
        self.storage.initialize()
        return self.ml().drift(model_id=model_id, dataset_id=dataset_id)

    def detection_status(self) -> dict[str, object]:
        self.storage.initialize()
        return self.detection().status()

    def detection_policies(self) -> list[dict[str, object]]:
        self.storage.initialize()
        return self.detection().policies_list()

    def detection_policy(
        self,
        policy_id: str,
        policy_version: str | None = None,
    ) -> dict[str, object]:
        self.storage.initialize()
        return self.detection().policy_show(policy_id, policy_version)

    def detection_activate_policy(
        self,
        policy_id: str,
        policy_version: str | None = None,
        *,
        confirm: bool = False,
        reason: str = "manual policy activation",
    ) -> dict[str, object]:
        self.storage.initialize()
        return self.detection().activate_policy(
            policy_id,
            policy_version,
            confirm=confirm,
            reason=reason,
        )

    def detection_rules(self) -> list[dict[str, object]]:
        self.storage.initialize()
        return self.detection().rules_list()

    def detection_run_once(
        self,
        *,
        dataset_kind: str = "synthetic",
        profile: str | None = None,
        policy_id: str | None = None,
        policy_version: str | None = None,
        model_id: str | None = None,
        start: datetime | None = None,
        end: datetime | None = None,
        batch_size: int = 256,
        max_windows: int | None = None,
        rules_only: bool = False,
        dry_run: bool = False,
    ) -> dict[str, object]:
        self.storage.initialize()
        return self.detection().run_once(
            dataset_kind=dataset_kind,
            profile=profile,
            policy_id=policy_id,
            policy_version=policy_version,
            model_id=model_id,
            start=start,
            end=end,
            batch_size=batch_size,
            max_windows=max_windows,
            rules_only=rules_only,
            dry_run=dry_run,
        )

    def detection_backfill(
        self,
        *,
        dataset_kind: str = "synthetic",
        policy_id: str | None = None,
        policy_version: str | None = None,
        model_id: str | None = None,
        start: datetime | None = None,
        end: datetime | None = None,
        registered_dataset_id: str | None = None,
        confirm: bool = False,
        advance_watermark: bool = False,
        confirm_advance_watermark: bool = False,
    ) -> dict[str, object]:
        self.storage.initialize()
        return self.detection().backfill(
            dataset_kind=dataset_kind,
            policy_id=policy_id,
            policy_version=policy_version,
            model_id=model_id,
            start=start,
            end=end,
            registered_dataset_id=registered_dataset_id,
            confirm=confirm,
            advance_watermark=advance_watermark,
            confirm_advance_watermark=confirm_advance_watermark,
        )

    def detection_runs(self) -> list[dict[str, object]]:
        self.storage.initialize()
        return self.detection().runs_list()

    def detection_run(self, detection_run_id: str) -> dict[str, object] | None:
        self.storage.initialize()
        return self.detection().run_show(detection_run_id)

    def detection_findings(
        self,
        *,
        status: str | None = None,
        dataset_kind: str | None = None,
    ) -> list[dict[str, object]]:
        self.storage.initialize()
        return self.detection().findings_list(status=status, dataset_kind=dataset_kind)

    def detection_finding(self, finding_id: str) -> dict[str, object] | None:
        self.storage.initialize()
        return self.detection().finding_show(finding_id)

    def detection_transition_finding(
        self,
        finding_id: str,
        *,
        to_status: str,
        reason: str,
        confirm: bool = False,
    ) -> dict[str, object]:
        self.storage.initialize()
        return self.detection().transition_finding(
            finding_id,
            to_status=to_status,
            reason=reason,
            confirm=confirm,
        )

    def detection_suppressions(self) -> list[dict[str, object]]:
        self.storage.initialize()
        return self.detection().suppressions_list()

    def detection_create_suppression(
        self,
        *,
        scope: str,
        reason: str,
        ttl_minutes: int,
        dataset_kind: str | None = None,
        profile_key: str | None = None,
        finding_fingerprint: str | None = None,
        signal_id: str | None = None,
    ) -> dict[str, object]:
        self.storage.initialize()
        return self.detection().create_suppression(
            scope=scope,
            reason=reason,
            ttl_minutes=ttl_minutes,
            dataset_kind=dataset_kind,
            profile_key_value=profile_key,
            finding_fingerprint=finding_fingerprint,
            signal_id=signal_id,
        )

    def detection_revoke_suppression(
        self,
        suppression_id: str,
        *,
        confirm: bool = False,
    ) -> dict[str, object]:
        self.storage.initialize()
        return self.detection().revoke_suppression(suppression_id, confirm=confirm)

    def detection_worker_status(self) -> dict[str, object]:
        self.storage.initialize()
        return get_detection_worker_manager().status(
            database_path=self.settings.database_path,
            data_dir=self.settings.data_dir,
            model_dir=self.settings.model_dir,
        )

    def detection_worker_start(
        self,
        *,
        dataset_kind: str = "synthetic",
        interval_seconds: int = 60,
    ) -> dict[str, object]:
        self.storage.initialize()
        return get_detection_worker_manager().start(
            database_path=self.settings.database_path,
            data_dir=self.settings.data_dir,
            model_dir=self.settings.model_dir,
            dataset_kind=dataset_kind,
            interval_seconds=interval_seconds,
        )

    def detection_worker_stop(self, *, confirm: bool = False) -> dict[str, object]:
        self.storage.initialize()
        return get_detection_worker_manager().stop(
            database_path=self.settings.database_path,
            data_dir=self.settings.data_dir,
            model_dir=self.settings.model_dir,
            dataset_kind=None,
            confirm=confirm,
        )

    def detection_worker_run_foreground(
        self,
        *,
        dataset_kind: str = "synthetic",
        max_windows: int | None = 256,
        interval_seconds: int = 60,
        single_cycle: bool = False,
    ) -> dict[str, object]:
        self.storage.initialize()
        return self.detection().worker_run_foreground(
            dataset_kind=dataset_kind,
            max_windows=max_windows,
            interval_seconds=interval_seconds,
            single_cycle=single_cycle,
        )

    def _create_dataset_locked(self, dataset_kind: str) -> dict[str, object]:
        self.materializer().materialize(dataset_kind)
        return self.snapshots().create(dataset_kind)

    def _train_from_latest_materialization(
        self,
        dataset_kind: str,
        seed: int,
    ) -> dict[str, object]:
        self.materializer().materialize(dataset_kind)
        return self.ml().train(dataset_kind=dataset_kind, seed=seed)

    def _ml_train_locked(
        self,
        *,
        dataset_kind: str,
        dataset_id: str | None,
        families: list[str] | None,
        seed: int,
        target_fpr: float,
        autoencoder_config: dict[str, object] | None,
        isolation_forest_config: dict[str, object] | None,
    ) -> dict[str, object]:
        if dataset_id is None:
            self.materializer().materialize(dataset_kind)
        return self.ml().train(
            dataset_kind=dataset_kind,
            dataset_id=dataset_id,
            families=families,
            seed=seed,
            target_fpr=target_fpr,
            autoencoder_config=autoencoder_config,
            isolation_forest_config=isolation_forest_config,
            auto_promote_synthetic=False,
        )

    def _with_feature_lock(
        self,
        dataset_kind: str,
        action: Callable[[], dict[str, object]],
    ) -> dict[str, object]:
        if dataset_kind not in _FEATURE_LOCKS:
            raise ValueError("dataset_kind must be synthetic or real")
        lock = _FEATURE_LOCKS[dataset_kind]
        if not lock.acquire(blocking=False):
            raise ValueError(f"{dataset_kind} materialization is already running")
        try:
            result = action()
        finally:
            lock.release()
        return result

    @staticmethod
    def _evaluation_windows(
        windows: list[WindowFeatures],
        training_range: dict[str, str] | None,
    ) -> list[WindowFeatures]:
        if not training_range or "end" not in training_range:
            split = max(8, int(len(windows) * 0.62))
            return windows[split:]
        training_end = training_range["end"]
        return [
            window
            for window in windows
            if window.window_start.isoformat() >= training_end
        ]


def window_from_snapshot_row(row: dict[str, object]) -> WindowFeatures:
    return WindowFeatures(
        window_start=_parse_snapshot_time(str(row["window_start"])),
        window_end=_parse_snapshot_time(str(row["window_end"])),
        user_id=str(row["user_id"]),
        host_id=str(row["host_id"]),
        features={name: float(str(row[name])) for name in FEATURE_NAMES},
    )


def _parse_snapshot_time(value: str) -> datetime:
    return datetime.fromisoformat(value.replace("Z", "+00:00"))
