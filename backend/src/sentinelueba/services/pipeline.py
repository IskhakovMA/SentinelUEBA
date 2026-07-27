from __future__ import annotations

import shutil
from pathlib import Path

from sentinelueba.collectors.manager import (
    CollectionAlreadyRunningError,
    CollectionStopTimeoutError,
    NoAvailableCollectorsError,
    get_manager,
)
from sentinelueba.config import Settings
from sentinelueba.detection.engine import detect_anomalies, summarize_scores
from sentinelueba.detection.scenario_validation import validate_demo_scenarios
from sentinelueba.domain.events import WindowFeatures
from sentinelueba.features.windows import build_feature_windows, windows_to_matrix
from sentinelueba.ml.autoencoder import load_model, model_info, train_autoencoder
from sentinelueba.normalization.normalizer import normalize_events
from sentinelueba.storage.sqlite import SQLiteStorage
from sentinelueba.telemetry.synthetic import generate_synthetic_events, scenario_manifest_for_start


class DemoPipeline:
    def __init__(self, settings: Settings) -> None:
        self.settings = settings
        self.settings.ensure_dirs()
        self.storage = SQLiteStorage(settings.database_path)

    def model_dir(self, dataset_kind: str = "synthetic") -> Path:
        return self.settings.model_dir / dataset_kind

    def initialize(self) -> dict[str, object]:
        self.storage.initialize()
        return self.status()

    def generate_demo_data(self, seed: int = 42) -> dict[str, object]:
        self.storage.initialize()
        events, summary = generate_synthetic_events(seed=seed)
        normalized = normalize_events(events)
        inserted = self.storage.insert_events(normalized)
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
        if dataset_kind == "real":
            eligibility = self.training_eligibility("real")
            if not eligibility["eligible"]:
                raise ValueError(f"real training not eligible: {eligibility['reason']}")
        events = self.storage.list_events(synthetic=(dataset_kind == "synthetic"))
        windows = build_feature_windows(events)
        if len(windows) < 12:
            raise ValueError(f"not enough {dataset_kind} feature windows for training")
        split = max(8, int(len(windows) * 0.62))
        train_windows = windows[:split]
        matrix = windows_to_matrix(train_windows)
        profile = {"user_id": train_windows[0].user_id, "host_id": train_windows[0].host_id}
        training_range = {
            "start": train_windows[0].window_start.isoformat(),
            "end": train_windows[-1].window_end.isoformat(),
        }
        _, preprocessor, losses = train_autoencoder(
            matrix,
            self.model_dir(dataset_kind),
            seed=seed,
            dataset_kind=dataset_kind,
            profile=profile,
            training_range=training_range,
        )
        return {
            "trained": True,
            "dataset_kind": dataset_kind,
            "training_windows": len(train_windows),
            "total_windows": len(windows),
            "evaluation_windows": max(0, len(windows) - split),
            "threshold": preprocessor.threshold,
            "final_loss": losses[-1],
            "training_range": training_range,
            "model_dir": str(self.model_dir(dataset_kind)),
        }

    def detect(self, dataset_kind: str = "synthetic") -> dict[str, object]:
        self.storage.initialize()
        events = self.storage.list_events(synthetic=(dataset_kind == "synthetic"))
        windows = build_feature_windows(events)
        model, preprocessor = load_model(self.model_dir(dataset_kind))
        evaluation_windows = self._evaluation_windows(windows, preprocessor.training_range)
        anomalies = detect_anomalies(
            model,
            preprocessor,
            evaluation_windows,
            range_kind="evaluation",
        )
        self.storage.replace_anomalies(anomalies)
        anomaly_payload = [item.model_dump(mode="json") for item in anomalies]
        scenario_validation = []
        if dataset_kind == "synthetic" and windows:
            scenario_validation = validate_demo_scenarios(
                scenario_manifest_for_start(windows[0].window_start),
                anomaly_payload,
            )
        return {
            "windows": len(windows),
            "evaluation_windows": len(evaluation_windows),
            "anomalies": len(anomalies),
            "summary": summarize_scores(anomalies),
            "top_anomalies": anomaly_payload[:5],
            "scenario_validation": scenario_validation,
        }

    def status(self) -> dict[str, object]:
        self.storage.initialize()
        storage_status = self.storage.status()
        info = model_info(self.model_dir("synthetic"))
        return {
            "project": "SentinelUEBA",
            "stage": "Stage 1",
            "windows_only": True,
            "storage": storage_status,
            "model": info,
            "collection": self.collection_status(),
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
        synthetic = dataset_kind == "synthetic"
        events = self.storage.list_events(synthetic=synthetic)
        windows = build_feature_windows(events)
        if dataset_kind == "synthetic":
            return {
                "dataset_kind": dataset_kind,
                "eligible": len(windows) >= 12,
                "reason": "ready" if len(windows) >= 12 else "not enough synthetic windows",
                "windows": len(windows),
            }
        progress = self.storage.collection_progress()
        enough_duration = float(progress["cumulative_collected_seconds"]) >= 24 * 60 * 60
        enough_windows = len(windows) >= 96
        reason = "ready"
        if not enough_duration:
            reason = "requires 24 cumulative hours of real collection"
        elif not enough_windows:
            reason = "not enough real feature windows"
        return {
            "dataset_kind": dataset_kind,
            "eligible": enough_duration and enough_windows,
            "reason": reason,
            "windows": len(windows),
            "cumulative_collected_seconds": progress["cumulative_collected_seconds"],
            "strict_continuous_24h_validated": progress["strict_continuous_24h_validated"],
        }

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
