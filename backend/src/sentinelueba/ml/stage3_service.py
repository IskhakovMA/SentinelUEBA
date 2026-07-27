from __future__ import annotations

import hashlib
import json
import re
import shutil
import subprocess
import time
from dataclasses import asdict
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, cast
from uuid import uuid4

import numpy as np
from sklearn.metrics import average_precision_score, precision_recall_fscore_support, roc_auc_score

from sentinelueba import __version__
from sentinelueba.datasets import DatasetSnapshotService
from sentinelueba.detection.engine import classify_risk
from sentinelueba.domain.events import AnomalyRecord
from sentinelueba.features.windows import FEATURE_NAMES, FEATURE_SCHEMA_VERSION
from sentinelueba.ml.stage3_calibration import ThresholdCalibrator
from sentinelueba.ml.stage3_contracts import LifecycleStatus, ModelFamily, PreprocessorV1
from sentinelueba.ml.stage3_models import (
    AutoencoderV2Config,
    AutoencoderV2Model,
    IsolationForestV1Config,
    IsolationForestV1Model,
    model_from_family,
)
from sentinelueba.ml.stage3_split import SplitPlan, create_split_plan, split_matrices, split_rows
from sentinelueba.storage.sqlite import SQLiteStorage

MODEL_ID_PATTERN = re.compile(r"^(autoencoder|isolation-forest)-[0-9]{14}-[a-f0-9]{8}$")
MODEL_BUNDLE_VERSION = "model-bundle-v1"


class ModelRegistryError(ValueError):
    pass


class ModelBundleVerificationError(ModelRegistryError):
    pass


def profile_key(profile: dict[str, str]) -> str:
    payload = json.dumps(profile, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()[:16]


class ModelBundleVerifier:
    def __init__(self, storage: SQLiteStorage, models_dir: Path) -> None:
        self.storage = storage
        self.models_dir = models_dir
        self.models_dir.mkdir(parents=True, exist_ok=True)

    def bundle_dir(self, model_id: str) -> Path:
        if not MODEL_ID_PATTERN.fullmatch(model_id):
            raise ModelBundleVerificationError("unsafe model id")
        path = (self.models_dir / model_id).resolve()
        if path.parent != self.models_dir.resolve():
            raise ModelBundleVerificationError("model path escapes models directory")
        return path

    def verify(self, model_id: str) -> dict[str, Any]:
        bundle_dir = self.bundle_dir(model_id)
        registry = self.storage.get_model_version(model_id)
        if registry is None:
            raise ModelBundleVerificationError("model bundle is not registered")
        if not bundle_dir.exists():
            raise ModelBundleVerificationError("model bundle directory is missing")
        manifest = _read_json(bundle_dir / "manifest.json")
        if manifest.get("model_id") != model_id:
            raise ModelBundleVerificationError("manifest model id mismatch")
        family = str(manifest.get("family"))
        artifact_name = _artifact_name(family)
        required = [
            "manifest.json",
            "split.json",
            "preprocessor.json",
            "metrics.json",
            "model_card.md",
            "checksums.sha256",
            artifact_name,
        ]
        checksums = _read_checksums(bundle_dir / "checksums.sha256")
        for filename in required:
            if not (bundle_dir / filename).exists():
                raise ModelBundleVerificationError(f"{filename} is missing")
            if filename != "checksums.sha256" and checksums.get(filename) != _sha_file(
                bundle_dir / filename
            ):
                raise ModelBundleVerificationError(f"{filename} SHA-256 mismatch")
        if registry["manifest_sha256"] != _sha_file(bundle_dir / "manifest.json"):
            raise ModelBundleVerificationError("SQLite manifest SHA-256 mismatch")
        if registry["model_artifact_sha256"] != _sha_file(bundle_dir / artifact_name):
            raise ModelBundleVerificationError("SQLite model artifact SHA-256 mismatch")
        preprocessor = _read_json(bundle_dir / "preprocessor.json")
        split = _read_json(bundle_dir / "split.json")
        metrics = _read_json(bundle_dir / "metrics.json")
        if manifest.get("bundle_version") != MODEL_BUNDLE_VERSION:
            raise ModelBundleVerificationError("unsupported model bundle version")
        if manifest.get("feature_schema_version") != FEATURE_SCHEMA_VERSION:
            raise ModelBundleVerificationError("feature schema mismatch")
        if manifest.get("feature_names") != FEATURE_NAMES:
            raise ModelBundleVerificationError("feature names/order mismatch")
        if preprocessor.get("feature_names") != FEATURE_NAMES:
            raise ModelBundleVerificationError("preprocessor feature names/order mismatch")
        if split.get("split_id") != registry["split_id"]:
            raise ModelBundleVerificationError("split id mismatch")
        if split.get("manifest_sha256") != manifest.get("split_manifest_sha256"):
            raise ModelBundleVerificationError("split SHA-256 mismatch")
        if manifest.get("threshold") != registry["threshold"]:
            raise ModelBundleVerificationError("threshold mismatch")
        for key in ["threshold", "training_duration_seconds", "inference_duration_seconds"]:
            value = manifest.get(key, 0.0)
            if not np.isfinite(float(value)):
                raise ModelBundleVerificationError(f"{key} is not finite")
        if metrics.get("label_status") not in {"labeled", "unlabeled"}:
            raise ModelBundleVerificationError("invalid evaluation label status")
        self._load_artifact(family, bundle_dir / artifact_name)
        return {
            "model_id": model_id,
            "verified": True,
            "manifest_sha256": registry["manifest_sha256"],
            "model_artifact_sha256": registry["model_artifact_sha256"],
            "family": family,
            "dataset_id": registry["dataset_id"],
            "threshold": registry["threshold"],
        }

    def load(self, model_id: str) -> tuple[dict[str, Any], PreprocessorV1, Any]:
        self.verify(model_id)
        bundle_dir = self.bundle_dir(model_id)
        manifest = _read_json(bundle_dir / "manifest.json")
        family = str(manifest["family"])
        artifact_name = _artifact_name(family)
        preprocessor = PreprocessorV1(**_read_json(bundle_dir / "preprocessor.json"))
        return manifest, preprocessor, self._load_artifact(family, bundle_dir / artifact_name)

    def _load_artifact(
        self,
        family: str,
        path: Path,
    ) -> AutoencoderV2Model | IsolationForestV1Model:
        if family == ModelFamily.AUTOENCODER.value:
            return AutoencoderV2Model.load_verified_artifact(path)
        if family == ModelFamily.ISOLATION_FOREST.value:
            return IsolationForestV1Model.load_verified_artifact(path)
        raise ModelBundleVerificationError("unsupported model family")


class Stage3MLService:
    def __init__(self, storage: SQLiteStorage, data_dir: Path, model_dir: Path) -> None:
        self.storage = storage
        self.snapshots = DatasetSnapshotService(storage, data_dir)
        self.models_dir = model_dir.parent / "models"
        self.verifier = ModelBundleVerifier(storage, self.models_dir)

    def status(self) -> dict[str, Any]:
        models = self.storage.list_model_versions()
        return {
            "schema_version": self.storage.status()["schema_version"],
            "models": models[:10],
            "champions": [
                model
                for model in models
                if model["lifecycle_status"] == LifecycleStatus.CHAMPION.value
            ],
            "training_runs": self.storage.list_training_runs()[:10],
            "scoring_runs": self.storage.list_scoring_runs()[:10],
            "legacy_unregistered": False,
        }

    def train(
        self,
        *,
        dataset_kind: str = "synthetic",
        dataset_id: str | None = None,
        families: list[str] | None = None,
        seed: int = 42,
        target_fpr: float = 0.05,
        autoencoder_config: dict[str, Any] | None = None,
        isolation_forest_config: dict[str, Any] | None = None,
        auto_promote_synthetic: bool = True,
    ) -> dict[str, Any]:
        self.storage.initialize()
        if dataset_id is None:
            dataset_id = str(self.snapshots.create(dataset_kind)["dataset_id"])
        matrix, manifest, rows = self.snapshots.load_matrix(dataset_id)
        dataset_manifest_sha256 = str(manifest["verification"]["manifest_sha256"])
        split = create_split_plan(rows, manifest, dataset_manifest_sha256=dataset_manifest_sha256)
        train_matrix, calibration_matrix, test_matrix = split_matrices(rows, split)
        train_rows, calibration_rows, test_rows = split_rows(rows, split)
        preprocessor = PreprocessorV1.fit(train_matrix)
        scaled_train = preprocessor.transform(train_matrix)
        scaled_calibration = preprocessor.transform(calibration_matrix)
        scaled_test = preprocessor.transform(test_matrix)
        selected_families = families or [
            ModelFamily.AUTOENCODER.value,
            ModelFamily.ISOLATION_FOREST.value,
        ]
        training_run_id = f"train-{datetime.now(UTC).strftime('%Y%m%d%H%M%S')}-{uuid4().hex[:8]}"
        effective_config = {
            "families": selected_families,
            "target_fpr": target_fpr,
            "autoencoder": autoencoder_config or asdict(AutoencoderV2Config()),
            "isolation_forest": isolation_forest_config or asdict(IsolationForestV1Config()),
        }
        now = datetime.now(UTC).isoformat()
        self.storage.create_training_run(
            {
                "training_run_id": training_run_id,
                "dataset_id": dataset_id,
                "dataset_manifest_sha256": dataset_manifest_sha256,
                "dataset_kind": manifest["dataset_kind"],
                "profile_key": profile_key(manifest["profile"]),
                "split_id": split.split_id,
                "split_manifest_sha256": split.manifest_sha256,
                "effective_config_json": json.dumps(effective_config, sort_keys=True),
                "config_sha256": _sha_json(effective_config),
                "seed": seed,
                "status": "running",
                "started_at": now,
                "application_version": __version__,
                "source_commit": _source_commit(),
            }
        )
        candidates: list[dict[str, Any]] = []
        try:
            for family_value in selected_families:
                family = ModelFamily(family_value)
                parameters = (
                    autoencoder_config or asdict(AutoencoderV2Config())
                    if family == ModelFamily.AUTOENCODER
                    else isolation_forest_config or asdict(IsolationForestV1Config())
                )
                started = time.perf_counter()
                model = model_from_family(family, parameters)
                model.fit(scaled_train, seed=seed)
                train_duration = time.perf_counter() - started
                calibration_scores = model.score(scaled_calibration).scores
                calibration = ThresholdCalibrator(target_false_positive_rate=target_fpr).calibrate(
                    calibration_scores
                )
                test_started = time.perf_counter()
                test_batch = model.score(scaled_test)
                inference_duration = time.perf_counter() - test_started
                metrics = self._evaluate(
                    manifest=manifest,
                    split=split,
                    test_rows=test_rows,
                    scores=test_batch.scores,
                    threshold=calibration.threshold,
                    inference_duration=inference_duration,
                )
                model_id = _model_id(family)
                explanation_kind = test_batch.explanation_kind
                if family == ModelFamily.AUTOENCODER:
                    autoencoder = cast(AutoencoderV2Model, model)
                    explanations = autoencoder.residual_contributions(
                        scaled_test,
                        FEATURE_NAMES,
                        test_matrix,
                        preprocessor,
                    )
                    explanation_kind = "autoencoder_reconstruction_contribution"
                else:
                    explanations = [
                        preprocessor.context_deviations(row)
                        for row in test_matrix
                    ]
                manifest_payload = self._bundle_manifest(
                    model_id=model_id,
                    family=family,
                    model_version=model.version,
                    dataset_manifest=manifest,
                    dataset_manifest_sha256=dataset_manifest_sha256,
                    split=split,
                    threshold=calibration.threshold,
                    calibration=calibration.to_dict(),
                    metrics=metrics,
                    train_duration=train_duration,
                    inference_duration=inference_duration,
                    effective_config=parameters,
                    seed=seed,
                    explanation_kind=explanation_kind,
                )
                bundle = self._create_bundle(
                    model_id=model_id,
                    model=model,
                    family=family,
                    manifest=manifest_payload,
                    split=split,
                    preprocessor=preprocessor,
                    metrics=metrics,
                    explanations=explanations,
                )
                self.storage.register_model_version(
                    {
                        "model_id": model_id,
                        "training_run_id": training_run_id,
                        "family": family.value,
                        "model_version": model.version,
                        "dataset_id": dataset_id,
                        "dataset_manifest_sha256": dataset_manifest_sha256,
                        "dataset_kind": manifest["dataset_kind"],
                        "profile_key": profile_key(manifest["profile"]),
                        "feature_schema_version": FEATURE_SCHEMA_VERSION,
                        "split_id": split.split_id,
                        "artifact_path": str(bundle["bundle_dir"]),
                        "manifest_sha256": bundle["manifest_sha256"],
                        "model_artifact_sha256": bundle["model_artifact_sha256"],
                        "lifecycle_status": LifecycleStatus.CANDIDATE.value,
                        "threshold": calibration.threshold,
                        "created_at": datetime.now(UTC).isoformat(),
                        "verified_at": datetime.now(UTC).isoformat(),
                    }
                )
                verification = self.verifier.verify(model_id)
                self.storage.record_model_evaluation(
                    {
                        "evaluation_id": f"eval-{uuid4().hex[:12]}",
                        "model_id": model_id,
                        "dataset_id": dataset_id,
                        "split_id": split.split_id,
                        "label_status": metrics["label_status"],
                        "metrics": metrics,
                        "created_at": datetime.now(UTC).isoformat(),
                    }
                )
                candidates.append(
                    {
                        "model_id": model_id,
                        "family": family.value,
                        "model_version": model.version,
                        "threshold": calibration.threshold,
                        "calibration": calibration.to_dict(),
                        "metrics": metrics,
                        "verification": verification,
                        "train_duration_seconds": train_duration,
                        "inference_duration_seconds": inference_duration,
                    }
                )
            recommended = self._recommend(candidates, manifest["dataset_kind"])
            if recommended is not None:
                self.storage.update_model_lifecycle(
                    str(recommended["model_id"]),
                    LifecycleStatus.RECOMMENDED.value,
                    verified_at=datetime.now(UTC).isoformat(),
                )
                if manifest["dataset_kind"] == "synthetic" and auto_promote_synthetic:
                    metrics = recommended["metrics"]
                    if (
                        metrics.get("scenario_recall") == 1.0
                        and metrics.get("false_positive_rate", 1) <= 0.15
                    ):
                        self.promote(
                            str(recommended["model_id"]),
                            confirm=True,
                            reason="synthetic auto-promotion gate passed",
                        )
            self.storage.complete_training_run(
                training_run_id,
                status="success",
                completed_at=datetime.now(UTC).isoformat(),
            )
            return {
                "training_run_id": training_run_id,
                "dataset_id": dataset_id,
                "dataset_manifest_sha256": dataset_manifest_sha256,
                "split": split.to_manifest(),
                "candidates": candidates,
                "recommended_model_id": recommended["model_id"] if recommended else None,
            }
        except Exception as exc:
            self.storage.complete_training_run(
                training_run_id,
                status="failed",
                completed_at=datetime.now(UTC).isoformat(),
                error_class=type(exc).__name__,
                safe_error_message=str(exc)[:500],
            )
            raise

    def verify_model(self, model_id: str) -> dict[str, Any]:
        return self.verifier.verify(model_id)

    def list_models(self) -> list[dict[str, Any]]:
        return self.storage.list_model_versions()

    def show_model(self, model_id: str) -> dict[str, Any]:
        model = self.storage.get_model_version(model_id)
        if model is None:
            raise ModelRegistryError("model is not registered")
        evaluation = self.storage.latest_model_evaluation(model_id)
        return {
            "model": model,
            "evaluation": evaluation,
            "verification": self.verify_model(model_id),
        }

    def promote(
        self,
        model_id: str,
        *,
        confirm: bool,
        reason: str = "manual promotion",
    ) -> dict[str, Any]:
        if not confirm:
            raise ModelRegistryError("promotion requires confirmation")
        model = self.storage.get_model_version(model_id)
        if model is None:
            raise ModelRegistryError("model is not registered")
        self.verify_model(model_id)
        self.snapshots.verify(str(model["dataset_id"]))
        if self.storage.latest_model_evaluation(model_id) is None:
            raise ModelRegistryError("model evaluation is required before promotion")
        return self.storage.promote_model(
            promotion_id=f"promotion-{uuid4().hex[:12]}",
            model_id=model_id,
            action="promote",
            reason=reason,
            created_at=datetime.now(UTC).isoformat(),
        )

    def retire(
        self,
        model_id: str,
        *,
        confirm: bool,
        reason: str = "manual retirement",
    ) -> dict[str, Any]:
        if not confirm:
            raise ModelRegistryError("retirement requires confirmation")
        self.verify_model(model_id)
        return self.storage.retire_model(
            promotion_id=f"promotion-{uuid4().hex[:12]}",
            model_id=model_id,
            reason=reason,
            created_at=datetime.now(UTC).isoformat(),
        )

    def rollback(
        self,
        model_id: str,
        *,
        confirm: bool,
        reason: str = "manual rollback",
    ) -> dict[str, Any]:
        if not confirm:
            raise ModelRegistryError("rollback requires confirmation")
        return self.promote(model_id, confirm=True, reason=reason)

    def score(
        self,
        *,
        dataset_id: str,
        model_id: str | None = None,
        dataset_kind: str | None = None,
        sync_anomalies: bool = False,
    ) -> dict[str, Any]:
        matrix, manifest, rows = self.snapshots.load_matrix(dataset_id)
        key = profile_key(manifest["profile"])
        if model_id is None:
            champion = self.storage.champion_model(
                str(dataset_kind or manifest["dataset_kind"]),
                key,
            )
            if champion is None:
                raise ModelRegistryError("champion model is not available")
            model_id = str(champion["model_id"])
        model_record = self.storage.get_model_version(model_id)
        if model_record is None:
            raise ModelRegistryError("model is not registered")
        if model_record["dataset_kind"] != manifest["dataset_kind"]:
            raise ModelRegistryError("dataset kind is incompatible with model")
        if model_record["profile_key"] != key:
            raise ModelRegistryError("dataset profile is incompatible with model")
        if model_record["feature_schema_version"] != FEATURE_SCHEMA_VERSION:
            raise ModelRegistryError("feature schema is incompatible with model")
        model_manifest, preprocessor, model = self.verifier.load(model_id)
        if model_manifest["feature_names"] != FEATURE_NAMES:
            raise ModelRegistryError("feature names/order mismatch")
        scaled = preprocessor.transform(matrix)
        started = datetime.now(UTC)
        batch = model.score(scaled)
        threshold = float(model_manifest["threshold"])
        explanation_kind = str(model_manifest["explanation_kind"])
        if model_manifest["family"] == ModelFamily.AUTOENCODER.value:
            explanations = model.residual_contributions(scaled, FEATURE_NAMES, matrix, preprocessor)
        else:
            explanations = [preprocessor.context_deviations(row) for row in matrix]
        scored = []
        anomalies: list[AnomalyRecord] = []
        for row, score, explanation in zip(rows, batch.scores, explanations, strict=True):
            risk = classify_risk(float(score), threshold)
            is_anomaly = risk.value != "normal"
            scored_row = {
                "window_id": row["window_id"],
                "window_start": row["window_start"],
                "window_end": row["window_end"],
                "anomaly_score": float(score),
                "threshold": threshold,
                "is_anomaly": is_anomaly,
                "risk_level": risk.value,
                "explanation_kind": explanation_kind,
                "explanation": explanation,
            }
            scored.append(scored_row)
            if is_anomaly:
                anomalies.append(
                    AnomalyRecord(
                        timestamp=datetime.fromisoformat(str(row["window_start"])),
                        user_id=str(row["user_id"]),
                        host_id=str(row["host_id"]),
                        anomaly_score=float(score),
                        threshold=threshold,
                        risk_level=risk,
                        top_features=[str(item["feature_name"]) for item in explanation[:3]],
                        feature_contributions=explanation[:5],
                        explanation=(
                            "Offline statistical anomaly. An anomaly is not proof of "
                            "malicious activity."
                        ),
                        model_version=str(model_manifest["model_version"]),
                        window_start=datetime.fromisoformat(str(row["window_start"])),
                        window_end=datetime.fromisoformat(str(row["window_end"])),
                        range_kind="offline_scoring",
                    )
                )
        scoring_run_id = f"score-{datetime.now(UTC).strftime('%Y%m%d%H%M%S')}-{uuid4().hex[:8]}"
        self.storage.create_scoring_run(
            {
                "scoring_run_id": scoring_run_id,
                "model_id": model_id,
                "dataset_id": dataset_id,
                "dataset_manifest_sha256": manifest["verification"]["manifest_sha256"],
                "split_range": {"kind": "full_snapshot"},
                "status": "success",
                "threshold": threshold,
                "started_at": started.isoformat(),
                "completed_at": datetime.now(UTC).isoformat(),
                "window_count": len(rows),
                "anomaly_count": len(anomalies),
            },
            scored,
        )
        if sync_anomalies:
            self.storage.replace_anomalies(anomalies)
        return {
            "scoring_run_id": scoring_run_id,
            "model_id": model_id,
            "dataset_id": dataset_id,
            "window_count": len(rows),
            "anomaly_count": len(anomalies),
            "top_anomalies": sorted(
                scored,
                key=lambda item: item["anomaly_score"],
                reverse=True,
            )[:5],
        }

    def evaluate(self, model_id: str) -> dict[str, Any]:
        model = self.storage.get_model_version(model_id)
        if model is None:
            raise ModelRegistryError("model is not registered")
        return self.storage.latest_model_evaluation(model_id) or {}

    def compare(self, model_ids: list[str]) -> dict[str, Any]:
        models = [self.show_model(model_id) for model_id in model_ids]
        return {"models": models}

    def drift(self, *, model_id: str, dataset_id: str) -> dict[str, Any]:
        model_record = self.storage.get_model_version(model_id)
        if model_record is None:
            raise ModelRegistryError("model is not registered")
        _, model_manifest, train_rows = self.snapshots.load_matrix(str(model_record["dataset_id"]))
        _, target_manifest, target_rows = self.snapshots.load_matrix(dataset_id)
        if model_manifest["dataset_kind"] != target_manifest["dataset_kind"]:
            raise ModelRegistryError("dataset kind is incompatible")
        if profile_key(model_manifest["profile"]) != profile_key(target_manifest["profile"]):
            raise ModelRegistryError("dataset profile is incompatible")
        if len(train_rows) < 12 or len(target_rows) < 12:
            return {"status": "insufficient_data"}
        train = np.asarray([[float(row[name]) for name in FEATURE_NAMES] for row in train_rows])
        target = np.asarray([[float(row[name]) for name in FEATURE_NAMES] for row in target_rows])
        shifts = []
        for index, name in enumerate(FEATURE_NAMES):
            train_mean = float(np.mean(train[:, index]))
            train_std = float(np.std(train[:, index]) or 1.0)
            target_mean = float(np.mean(target[:, index]))
            standardized_mean_shift = abs(target_mean - train_mean) / train_std
            shifts.append(
                {
                    "feature_name": name,
                    "standardized_mean_shift": standardized_mean_shift,
                    "train_quantiles": _percentiles(train[:, index].tolist()),
                    "target_quantiles": _percentiles(target[:, index].tolist()),
                    "psi": _psi(train[:, index], target[:, index]),
                }
            )
        return {
            "status": "ok",
            "model_id": model_id,
            "dataset_id": dataset_id,
            "top_shifted_features": sorted(
                shifts,
                key=lambda item: cast(float, item["standardized_mean_shift"]),
                reverse=True,
            )[:5],
            "limitations": ["offline report only; no alerts or collection blocking"],
        }

    def _evaluate(
        self,
        *,
        manifest: dict[str, Any],
        split: SplitPlan,
        test_rows: list[dict[str, Any]],
        scores: list[float],
        threshold: float,
        inference_duration: float,
    ) -> dict[str, Any]:
        flagged = [score >= threshold for score in scores]
        base: dict[str, Any] = {
            "label_status": "unlabeled" if manifest["dataset_kind"] == "real" else "labeled",
            "train_count": split.train.count,
            "calibration_count": split.calibration.count,
            "test_count": split.test.count,
            "threshold": threshold,
            "flagged_window_rate": sum(flagged) / len(flagged) if flagged else 0.0,
            "score_percentiles": _percentiles(scores),
            "inference_duration_seconds": inference_duration,
            "windows_per_second": len(scores) / max(inference_duration, 1e-9),
        }
        if manifest["dataset_kind"] == "real":
            base.update(
                {
                    "test_flagged_rate": base["flagged_window_rate"],
                    "limitations": [
                        "real data is unlabeled",
                        "accuracy, precision, recall, F1, ROC-AUC and PR-AUC are not reported",
                    ],
                }
            )
            return base
        positives = set(split.scenario_window_ids)
        labels = [str(row["window_id"]) in positives for row in test_rows]
        tp = sum(1 for label, mark in zip(labels, flagged, strict=True) if label and mark)
        fp = sum(1 for label, mark in zip(labels, flagged, strict=True) if not label and mark)
        tn = sum(1 for label, mark in zip(labels, flagged, strict=True) if not label and not mark)
        fn = sum(1 for label, mark in zip(labels, flagged, strict=True) if label and not mark)
        precision, recall, f1, _ = precision_recall_fscore_support(
            labels,
            flagged,
            average="binary",
            zero_division=0,
        )
        normal_count = fp + tn
        base.update(
            {
                "window_true_positives": tp,
                "false_positives": fp,
                "true_negatives": tn,
                "false_negatives": fn,
                "precision": float(precision),
                "recall": float(recall),
                "f1": float(f1),
                "false_positive_rate": fp / normal_count if normal_count else 0.0,
                "roc_auc": float(roc_auc_score(labels, scores)) if len(set(labels)) == 2 else None,
                "pr_auc": float(average_precision_score(labels, scores))
                if len(set(labels)) == 2
                else None,
                "scenario_recall": tp / max(1, len(positives)),
                "detected_scenarios": tp,
                "missed_scenarios": fn,
                "scenario_window_ids": split.scenario_window_ids,
            }
        )
        return base

    def _recommend(
        self,
        candidates: list[dict[str, Any]],
        dataset_kind: str,
    ) -> dict[str, Any] | None:
        if not candidates or dataset_kind == "real":
            return None
        return sorted(
            candidates,
            key=lambda item: (
                float(item["metrics"].get("scenario_recall", 0.0)),
                -float(item["metrics"].get("false_positive_rate", 1.0)),
                float(item["metrics"].get("pr_auc") or 0.0),
                -float(item["inference_duration_seconds"]),
            ),
            reverse=True,
        )[0]

    def _bundle_manifest(
        self,
        *,
        model_id: str,
        family: ModelFamily,
        model_version: str,
        dataset_manifest: dict[str, Any],
        dataset_manifest_sha256: str,
        split: SplitPlan,
        threshold: float,
        calibration: dict[str, Any],
        metrics: dict[str, Any],
        train_duration: float,
        inference_duration: float,
        effective_config: dict[str, Any],
        seed: int,
        explanation_kind: str,
    ) -> dict[str, Any]:
        return {
            "bundle_version": MODEL_BUNDLE_VERSION,
            "model_id": model_id,
            "family": family.value,
            "model_version": model_version,
            "dataset_id": dataset_manifest["dataset_id"],
            "dataset_manifest_sha256": dataset_manifest_sha256,
            "dataset_kind": dataset_manifest["dataset_kind"],
            "profile": dataset_manifest["profile"],
            "profile_key": profile_key(dataset_manifest["profile"]),
            "feature_schema_version": FEATURE_SCHEMA_VERSION,
            "feature_names": FEATURE_NAMES,
            "split_id": split.split_id,
            "split_manifest_sha256": split.manifest_sha256,
            "threshold": threshold,
            "threshold_calibration": calibration,
            "metrics": metrics,
            "training_duration_seconds": train_duration,
            "inference_duration_seconds": inference_duration,
            "effective_config": effective_config,
            "seed": seed,
            "score_direction": "higher_is_more_anomalous",
            "explanation_kind": explanation_kind,
            "created_at": datetime.now(UTC).isoformat(),
            "application_version": __version__,
            "source_commit": _source_commit(),
        }

    def _create_bundle(
        self,
        *,
        model_id: str,
        model: Any,
        family: ModelFamily,
        manifest: dict[str, Any],
        split: SplitPlan,
        preprocessor: PreprocessorV1,
        metrics: dict[str, Any],
        explanations: list[list[dict[str, object]]],
    ) -> dict[str, Any]:
        bundle_dir = self.verifier.bundle_dir(model_id)
        tmp_dir = self.models_dir / f".tmp-{model_id}"
        if bundle_dir.exists() or tmp_dir.exists():
            raise ModelRegistryError("model bundle already exists")
        artifact_name = _artifact_name(family.value)
        try:
            tmp_dir.mkdir(parents=True)
            (tmp_dir / "split.json").write_text(
                json.dumps(split.to_manifest(), indent=2, sort_keys=True)
            )
            (tmp_dir / "preprocessor.json").write_text(
                json.dumps(asdict(preprocessor), indent=2, sort_keys=True)
            )
            (tmp_dir / "metrics.json").write_text(json.dumps(metrics, indent=2, sort_keys=True))
            model.save_artifact(tmp_dir / artifact_name)
            manifest["artifact_hashes"] = {
                "split_sha256": _sha_file(tmp_dir / "split.json"),
                "preprocessor_sha256": _sha_file(tmp_dir / "preprocessor.json"),
                "metrics_sha256": _sha_file(tmp_dir / "metrics.json"),
                "model_artifact_sha256": _sha_file(tmp_dir / artifact_name),
            }
            (tmp_dir / "model_card.md").write_text(_model_card(manifest, metrics))
            manifest["artifact_hashes"]["model_card_sha256"] = _sha_file(
                tmp_dir / "model_card.md"
            )
            manifest["example_explanation_kind"] = (
                manifest["explanation_kind"] if explanations else manifest["explanation_kind"]
            )
            (tmp_dir / "manifest.json").write_text(json.dumps(manifest, indent=2, sort_keys=True))
            checksum_lines = []
            for path in sorted(tmp_dir.iterdir(), key=lambda item: item.name):
                if path.name == "checksums.sha256":
                    continue
                checksum_lines.append(f"{_sha_file(path)}  {path.name}")
            (tmp_dir / "checksums.sha256").write_text("\n".join(checksum_lines) + "\n")
            tmp_dir.rename(bundle_dir)
            return {
                "bundle_dir": bundle_dir,
                "manifest_sha256": _sha_file(bundle_dir / "manifest.json"),
                "model_artifact_sha256": _sha_file(bundle_dir / artifact_name),
            }
        except Exception:
            if tmp_dir.exists():
                shutil.rmtree(tmp_dir)
            if bundle_dir.exists() and self.storage.get_model_version(model_id) is None:
                shutil.rmtree(bundle_dir)
            raise


def _model_card(manifest: dict[str, Any], metrics: dict[str, Any]) -> str:
    return "\n".join(
        [
            f"# Model Card: {manifest['model_id']}",
            "",
            f"- Family/version: {manifest['family']} / {manifest['model_version']}",
            "- Intended use: local offline anomaly scoring for registered SentinelUEBA snapshots.",
            "- Out-of-scope use: live alerts, proof of compromise, SIEM export, "
            "or automated response.",
            f"- Source dataset: {manifest['dataset_id']} ({manifest['dataset_kind']})",
            f"- Profile label: {manifest['profile_key']}",
            f"- Feature schema: {manifest['feature_schema_version']}",
            f"- Split id: {manifest['split_id']}",
            f"- Threshold method: {manifest['threshold_calibration']['method_version']}",
            f"- Threshold: {manifest['threshold']}",
            f"- Metrics: `{json.dumps(metrics, sort_keys=True)}`",
            "- Limitations: synthetic metrics are not production accuracy; real data is unlabeled.",
            "- Privacy: raw usernames, hostnames, paths, network addresses, payloads, "
            "and identity secrets are excluded.",
            "- Known telemetry gaps: collector coverage and feature quality should be "
            "reviewed before use.",
            "- Statement: An anomaly is not proof of malicious activity.",
            "- Artifact hashes: "
            f"`{json.dumps(manifest.get('artifact_hashes', {}), sort_keys=True)}`",
            f"- Application/source commit: {manifest['application_version']} / "
            f"{manifest['source_commit']}",
            "",
        ]
    )


def _model_id(family: ModelFamily) -> str:
    return f"{family.value}-{datetime.now(UTC).strftime('%Y%m%d%H%M%S')}-{uuid4().hex[:8]}"


def _artifact_name(family: str) -> str:
    return "autoencoder.pt" if family == ModelFamily.AUTOENCODER.value else "isolation_forest.skops"


def _read_json(path: Path) -> dict[str, Any]:
    try:
        payload = json.loads(path.read_text())
    except json.JSONDecodeError as exc:
        raise ModelBundleVerificationError(f"{path.name} is damaged") from exc
    if not isinstance(payload, dict):
        raise ModelBundleVerificationError(f"{path.name} must contain an object")
    return payload


def _read_checksums(path: Path) -> dict[str, str]:
    if not path.exists():
        raise ModelBundleVerificationError("checksums.sha256 is missing")
    checksums: dict[str, str] = {}
    for line in path.read_text().splitlines():
        parts = line.split()
        if len(parts) != 2:
            raise ModelBundleVerificationError("checksums.sha256 is damaged")
        checksums[parts[1]] = parts[0]
    return checksums


def _sha_file(path: Path) -> str:
    digest = hashlib.sha256()
    try:
        with path.open("rb") as handle:
            for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                digest.update(chunk)
    except FileNotFoundError as exc:
        raise ModelBundleVerificationError(f"{path.name} is missing") from exc
    return digest.hexdigest()


def _sha_json(payload: dict[str, Any]) -> str:
    return hashlib.sha256(
        json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()


def _source_commit() -> str:
    try:
        return subprocess.check_output(["git", "rev-parse", "HEAD"], text=True).strip()
    except Exception:
        return "unknown"


def _percentiles(scores: list[float]) -> dict[str, float]:
    if not scores:
        return {}
    values = np.asarray(scores, dtype=np.float64)
    return {
        "p05": float(np.percentile(values, 5)),
        "p50": float(np.percentile(values, 50)),
        "p95": float(np.percentile(values, 95)),
        "p99": float(np.percentile(values, 99)),
    }


def _psi(expected: np.ndarray, actual: np.ndarray, buckets: int = 10) -> float:
    quantiles = np.percentile(expected, np.linspace(0, 100, buckets + 1))
    quantiles[0] -= 1e-9
    quantiles[-1] += 1e-9
    expected_counts, _ = np.histogram(expected, bins=quantiles)
    actual_counts, _ = np.histogram(actual, bins=quantiles)
    expected_pct = expected_counts / max(1, expected_counts.sum())
    actual_pct = actual_counts / max(1, actual_counts.sum())
    total = 0.0
    for exp, act in zip(expected_pct, actual_pct, strict=True):
        exp = max(float(exp), 1e-6)
        act = max(float(act), 1e-6)
        total += (act - exp) * np.log(act / exp)
    return float(total)
