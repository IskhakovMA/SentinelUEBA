from __future__ import annotations

import shutil
from pathlib import Path

from sentinelueba.config import Settings
from sentinelueba.detection.engine import detect_anomalies, summarize_scores
from sentinelueba.features.windows import build_feature_windows, windows_to_matrix
from sentinelueba.ml.autoencoder import load_model, model_info, train_autoencoder
from sentinelueba.normalization.normalizer import normalize_events
from sentinelueba.storage.sqlite import SQLiteStorage
from sentinelueba.telemetry.synthetic import generate_synthetic_events


class DemoPipeline:
    def __init__(self, settings: Settings) -> None:
        self.settings = settings
        self.settings.ensure_dirs()
        self.storage = SQLiteStorage(settings.database_path)

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
        }

    def train(self, seed: int = 42) -> dict[str, object]:
        self.storage.initialize()
        events = self.storage.list_events()
        windows = build_feature_windows(events)
        if len(windows) < 12:
            raise ValueError("generate demo data before training")
        split = max(8, int(len(windows) * 0.62))
        train_windows = windows[:split]
        matrix = windows_to_matrix(train_windows)
        _, preprocessor, losses = train_autoencoder(matrix, self.settings.model_dir, seed=seed)
        return {
            "trained": True,
            "training_windows": len(train_windows),
            "total_windows": len(windows),
            "threshold": preprocessor.threshold,
            "final_loss": losses[-1],
            "model_dir": str(self.settings.model_dir),
        }

    def detect(self) -> dict[str, object]:
        self.storage.initialize()
        events = self.storage.list_events()
        windows = build_feature_windows(events)
        model, preprocessor = load_model(self.settings.model_dir)
        anomalies = detect_anomalies(model, preprocessor, windows)
        self.storage.replace_anomalies(anomalies)
        return {
            "windows": len(windows),
            "anomalies": len(anomalies),
            "summary": summarize_scores(anomalies),
            "top_anomalies": [item.model_dump(mode="json") for item in anomalies[:5]],
        }

    def status(self) -> dict[str, object]:
        self.storage.initialize()
        storage_status = self.storage.status()
        info = model_info(self.settings.model_dir)
        return {
            "project": "SentinelUEBA",
            "stage": "Stage 0",
            "windows_only": True,
            "storage": storage_status,
            "model": info,
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

