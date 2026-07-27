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
from sentinelueba.services.eligibility import EligibilityService
from sentinelueba.storage.sqlite import SQLiteStorage
from sentinelueba.telemetry.synthetic import scenario_manifest_for_start

MODEL_ID_PATTERN = re.compile(r"^(autoencoder|isolation-forest)-[0-9]{14}-[a-f0-9]{8}$")
MODEL_BUNDLE_VERSION = "model-bundle-v1"


class ModelRegistryError(ValueError):
    pass


class ModelBundleVerificationError(ModelRegistryError):
    pass


def profile_key(profile: dict[str, str]) -> str:
    payload = json.dumps(profile, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()[:16]


class ModelCompatibilityService:
    def __init__(self, storage: SQLiteStorage, data_dir: Path) -> None:
        self.storage = storage
        self.snapshots = DatasetSnapshotService(storage, data_dir)

    def verify_source(self, model_id: str) -> dict[str, Any]:
        model = self.storage.get_model_version(model_id)
        if model is None:
            raise ModelRegistryError("model is not registered")
        source_snapshot = self.storage.get_dataset_snapshot(str(model["dataset_id"]))
        if source_snapshot is None:
            raise ModelRegistryError("source dataset snapshot is not registered")
        source_verification = self.snapshots.verify(str(model["dataset_id"]))
        if source_snapshot["manifest_sha256"] != model["dataset_manifest_sha256"]:
            raise ModelRegistryError("model/source dataset manifest SHA-256 mismatch")
        if source_snapshot["dataset_kind"] != model["dataset_kind"]:
            raise ModelRegistryError("model/source dataset kind mismatch")
        if profile_key(source_snapshot["profile"]) != model["profile_key"]:
            raise ModelRegistryError("model/source dataset profile mismatch")
        if source_snapshot["feature_schema_version"] != FEATURE_SCHEMA_VERSION:
            raise ModelRegistryError("source feature schema is incompatible")
        return {
            "status": "ok",
            "model": model,
            "source_snapshot": source_snapshot,
            "source_verification": source_verification,
        }

    def verify_target(self, model_id: str, dataset_id: str) -> dict[str, Any]:
        source = self.verify_source(model_id)
        target_snapshot = self.storage.get_dataset_snapshot(dataset_id)
        if target_snapshot is None:
            raise ModelRegistryError("target dataset snapshot is not registered")
        target_verification = self.snapshots.verify(dataset_id)
        model = source["model"]
        if target_snapshot["dataset_kind"] != model["dataset_kind"]:
            raise ModelRegistryError("dataset kind is incompatible with model")
        if profile_key(target_snapshot["profile"]) != model["profile_key"]:
            raise ModelRegistryError("dataset profile is incompatible with model")
        if target_snapshot["feature_schema_version"] != FEATURE_SCHEMA_VERSION:
            raise ModelRegistryError("target feature schema is incompatible")
        target_manifest = target_snapshot["manifest"]
        if target_manifest.get("feature_names") != FEATURE_NAMES:
            raise ModelRegistryError("target feature names/order mismatch")
        return {
            **source,
            "target_snapshot": target_snapshot,
            "target_verification": target_verification,
            "target_dataset_id": dataset_id,
        }


class ModelBundleVerifier:
    def __init__(self, storage: SQLiteStorage, models_dir: Path, data_dir: Path) -> None:
        self.storage = storage
        self.models_dir = models_dir
        self.data_dir = data_dir
        self.compatibility = ModelCompatibilityService(storage, data_dir)
        self.models_dir.mkdir(parents=True, exist_ok=True)

    def bundle_dir(self, model_id: str) -> Path:
        if not MODEL_ID_PATTERN.fullmatch(model_id):
            raise ModelBundleVerificationError("unsafe model id")
        path = (self.models_dir / model_id).resolve()
        if path.parent != self.models_dir.resolve():
            raise ModelBundleVerificationError("model path escapes models directory")
        return path

    def verify_internal(
        self,
        model_id: str,
        bundle_dir: Path,
        *,
        expected_dataset_manifest: dict[str, Any],
        expected_dataset_manifest_sha256: str,
    ) -> dict[str, Any]:
        self._assert_safe_bundle_path(model_id, bundle_dir)
        manifest, split, preprocessor, metrics, artifact_name = self._verify_bundle_files(
            model_id,
            bundle_dir,
        )
        self._verify_dataset_contract(
            manifest,
            split,
            expected_dataset_manifest=expected_dataset_manifest,
            expected_dataset_manifest_sha256=expected_dataset_manifest_sha256,
        )
        artifact = self._load_artifact(str(manifest["family"]), bundle_dir / artifact_name)
        self._verify_model_input_dimension(artifact, preprocessor)
        return {
            "model_id": model_id,
            "verified": True,
            "mode": "internal",
            "family": manifest["family"],
            "dataset_id": manifest["dataset_id"],
            "threshold": manifest["threshold"],
            "label_status": metrics["label_status"],
        }

    def verify(self, model_id: str) -> dict[str, Any]:
        return self._verify_registered(model_id, allow_pending=False)

    def _verify_registered_pending(self, model_id: str) -> dict[str, Any]:
        return self._verify_registered(model_id, allow_pending=True)

    def _verify_registered(self, model_id: str, *, allow_pending: bool) -> dict[str, Any]:
        bundle_dir = self.bundle_dir(model_id)
        registry = self.storage.get_model_version(model_id)
        if registry is None:
            raise ModelBundleVerificationError("model bundle is not registered")
        if not allow_pending and registry["verified_at"] is None:
            raise ModelBundleVerificationError("model registration is not finalized")
        if Path(str(registry["artifact_path"])).resolve() != bundle_dir:
            raise ModelBundleVerificationError("SQLite artifact path mismatch")
        if not bundle_dir.exists():
            raise ModelBundleVerificationError("model bundle directory is missing")
        manifest, split, preprocessor, metrics, artifact_name = self._verify_bundle_files(
            model_id,
            bundle_dir,
        )
        self._verify_registry_contract(registry, manifest, artifact_name, bundle_dir)
        compatibility = self.compatibility.verify_source(model_id)
        source_snapshot = compatibility["source_snapshot"]
        training_run = self.storage.get_training_run(str(registry["training_run_id"]))
        if training_run is None:
            raise ModelBundleVerificationError("training run is missing")
        if not allow_pending and (
            training_run["status"] != "success" or training_run["completed_at"] is None
        ):
            raise ModelBundleVerificationError("model registration is not finalized")
        if allow_pending and training_run["status"] not in {"running", "success"}:
            raise ModelBundleVerificationError("model registration is not finalized")
        self._verify_training_run_contract(registry, training_run, manifest)
        self._verify_dataset_contract(
            manifest,
            split,
            expected_dataset_manifest=source_snapshot["manifest"],
            expected_dataset_manifest_sha256=str(source_snapshot["manifest_sha256"]),
        )
        artifact = self._load_artifact(str(manifest["family"]), bundle_dir / artifact_name)
        self._verify_model_input_dimension(artifact, preprocessor)
        return {
            "model_id": model_id,
            "verified": True,
            "mode": "public",
            "manifest_sha256": registry["manifest_sha256"],
            "model_artifact_sha256": registry["model_artifact_sha256"],
            "family": manifest["family"],
            "dataset_id": registry["dataset_id"],
            "threshold": registry["threshold"],
        }

    def _verify_training_run_contract(
        self,
        registry: dict[str, Any],
        training_run: dict[str, Any],
        manifest: dict[str, Any],
    ) -> None:
        comparisons = {
            "dataset_id": registry["dataset_id"],
            "dataset_manifest_sha256": registry["dataset_manifest_sha256"],
            "dataset_kind": registry["dataset_kind"],
            "profile_key": registry["profile_key"],
            "split_id": registry["split_id"],
        }
        for key, expected in comparisons.items():
            if training_run[key] != expected:
                raise ModelBundleVerificationError(f"training run {key} mismatch")
        if training_run["split_manifest_sha256"] != manifest["split_manifest_sha256"]:
            raise ModelBundleVerificationError("training run split SHA-256 mismatch")

    def _assert_safe_bundle_path(self, model_id: str, path: Path) -> None:
        if not MODEL_ID_PATTERN.fullmatch(model_id):
            raise ModelBundleVerificationError("unsafe model id")
        resolved = path.resolve()
        root = self.models_dir.resolve()
        if resolved.parent != root:
            raise ModelBundleVerificationError("model path escapes models directory")

    def _verify_bundle_files(
        self,
        model_id: str,
        bundle_dir: Path,
    ) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any], dict[str, Any], str]:
        self._assert_safe_bundle_path(model_id, bundle_dir)
        manifest = _read_json(bundle_dir / "manifest.json")
        if manifest.get("model_id") != model_id:
            raise ModelBundleVerificationError("manifest model id mismatch")
        family = str(manifest.get("family"))
        artifact_name = _artifact_name(family)
        allowed_artifacts = {artifact_name}
        unexpected = {
            path.name
            for path in bundle_dir.iterdir()
            if path.suffix in {".pt", ".skops", ".pkl", ".pickle"}
            and path.name not in allowed_artifacts
        }
        if unexpected:
            raise ModelBundleVerificationError("unexpected model artifact format")
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
        artifact_hashes = manifest.get("artifact_hashes")
        if not isinstance(artifact_hashes, dict):
            raise ModelBundleVerificationError("manifest artifact hashes are missing")
        expected_hash_keys = {
            "split_sha256": "split.json",
            "preprocessor_sha256": "preprocessor.json",
            "metrics_sha256": "metrics.json",
            "model_card_sha256": "model_card.md",
            "model_artifact_sha256": artifact_name,
        }
        if set(artifact_hashes) != set(expected_hash_keys):
            raise ModelBundleVerificationError("manifest artifact hashes contain unexpected keys")
        for filename in required:
            if not (bundle_dir / filename).exists():
                raise ModelBundleVerificationError(f"{filename} is missing")
            if filename == "checksums.sha256":
                continue
            actual = _sha_file(bundle_dir / filename)
            if checksums.get(filename) != actual:
                raise ModelBundleVerificationError(f"{filename} SHA-256 mismatch")
        for hash_key, filename in expected_hash_keys.items():
            actual = _sha_file(bundle_dir / filename)
            if artifact_hashes.get(hash_key) != actual:
                raise ModelBundleVerificationError(f"manifest {hash_key} mismatch")
            if checksums.get(filename) != artifact_hashes.get(hash_key):
                raise ModelBundleVerificationError(f"checksums {filename} mismatch")
        preprocessor = _read_json(bundle_dir / "preprocessor.json")
        split = _read_json(bundle_dir / "split.json")
        metrics = _read_json(bundle_dir / "metrics.json")
        if manifest.get("bundle_version") != MODEL_BUNDLE_VERSION:
            raise ModelBundleVerificationError("unsupported model bundle version")
        if manifest.get("feature_schema_version") != FEATURE_SCHEMA_VERSION:
            raise ModelBundleVerificationError("feature schema mismatch")
        if manifest.get("feature_names") != FEATURE_NAMES:
            raise ModelBundleVerificationError("feature names/order mismatch")
        self._verify_preprocessor(preprocessor)
        if split.get("manifest_sha256") != _split_manifest_sha256(split):
            raise ModelBundleVerificationError("split canonical SHA-256 mismatch")
        if split.get("manifest_sha256") != manifest.get("split_manifest_sha256"):
            raise ModelBundleVerificationError("split SHA-256 mismatch")
        if split.get("split_id") != manifest.get("split_id"):
            raise ModelBundleVerificationError("split id mismatch")
        for key in ["threshold", "training_duration_seconds", "inference_duration_seconds"]:
            value = manifest.get(key, 0.0)
            if not np.isfinite(float(value)):
                raise ModelBundleVerificationError(f"{key} is not finite")
        if manifest.get("score_direction") != "higher_is_more_anomalous":
            raise ModelBundleVerificationError("unsupported score direction")
        if metrics.get("threshold") != manifest.get("threshold"):
            raise ModelBundleVerificationError("metrics threshold mismatch")
        if metrics.get("label_status") not in {"labeled", "unlabeled"}:
            raise ModelBundleVerificationError("invalid evaluation label status")
        return manifest, split, preprocessor, metrics, artifact_name

    def _verify_preprocessor(self, preprocessor: dict[str, Any]) -> None:
        expected_keys = {
            "feature_names",
            "mean",
            "std",
            "median",
            "iqr",
            "feature_schema_version",
            "version",
        }
        if set(preprocessor) != expected_keys:
            raise ModelBundleVerificationError("preprocessor contains unexpected fields")
        if preprocessor.get("feature_names") != FEATURE_NAMES:
            raise ModelBundleVerificationError("preprocessor feature names/order mismatch")
        if preprocessor.get("feature_schema_version") != FEATURE_SCHEMA_VERSION:
            raise ModelBundleVerificationError("preprocessor feature schema mismatch")
        if preprocessor.get("version") != "preprocessor-v1":
            raise ModelBundleVerificationError("preprocessor version mismatch")
        for key in ["mean", "std", "median", "iqr"]:
            values = preprocessor.get(key)
            if not isinstance(values, list) or len(values) != len(FEATURE_NAMES):
                raise ModelBundleVerificationError(f"preprocessor {key} length mismatch")
            if not all(np.isfinite(float(value)) for value in values):
                raise ModelBundleVerificationError(f"preprocessor {key} contains non-finite values")
        if not all(float(value) > 0 for value in preprocessor["std"]):
            raise ModelBundleVerificationError("preprocessor std must be positive")
        if not all(float(value) > 0 for value in preprocessor["iqr"]):
            raise ModelBundleVerificationError("preprocessor iqr must be positive")

    def _verify_dataset_contract(
        self,
        manifest: dict[str, Any],
        split: dict[str, Any],
        *,
        expected_dataset_manifest: dict[str, Any],
        expected_dataset_manifest_sha256: str,
    ) -> None:
        if manifest.get("dataset_id") != expected_dataset_manifest.get("dataset_id"):
            raise ModelBundleVerificationError("dataset id mismatch")
        if manifest.get("dataset_manifest_sha256") != expected_dataset_manifest_sha256:
            raise ModelBundleVerificationError("dataset manifest SHA-256 mismatch")
        if manifest.get("dataset_kind") != expected_dataset_manifest.get("dataset_kind"):
            raise ModelBundleVerificationError("dataset kind mismatch")
        if manifest.get("profile") != expected_dataset_manifest.get("profile"):
            raise ModelBundleVerificationError("dataset profile mismatch")
        if manifest.get("feature_schema_version") != expected_dataset_manifest.get(
            "feature_schema_version"
        ):
            raise ModelBundleVerificationError("dataset feature schema mismatch")
        if manifest.get("feature_names") != expected_dataset_manifest.get("feature_names"):
            raise ModelBundleVerificationError("dataset feature names/order mismatch")
        if split.get("dataset_id") != manifest.get("dataset_id"):
            raise ModelBundleVerificationError("split dataset id mismatch")
        if split.get("dataset_manifest_sha256") != manifest.get("dataset_manifest_sha256"):
            raise ModelBundleVerificationError("split dataset hash mismatch")
        if split.get("dataset_kind") != manifest.get("dataset_kind"):
            raise ModelBundleVerificationError("split dataset kind mismatch")
        if split.get("profile") != manifest.get("profile"):
            raise ModelBundleVerificationError("split profile mismatch")
        if split.get("feature_schema_version") != FEATURE_SCHEMA_VERSION:
            raise ModelBundleVerificationError("split feature schema mismatch")
        if split.get("feature_names") != FEATURE_NAMES:
            raise ModelBundleVerificationError("split feature names/order mismatch")
        parts = [split.get("train"), split.get("calibration"), split.get("test")]
        ids: list[str] = []
        previous_end = ""
        for part in parts:
            if not isinstance(part, dict):
                raise ModelBundleVerificationError("split part is damaged")
            window_ids = part.get("window_ids")
            if not isinstance(window_ids, list):
                raise ModelBundleVerificationError("split window ids are damaged")
            if int(part.get("count", -1)) != len(window_ids):
                raise ModelBundleVerificationError("split count mismatch")
            if bool(window_ids) != bool(part.get("start") and part.get("end")):
                raise ModelBundleVerificationError("split range mismatch")
            if window_ids:
                start = str(part["start"])
                end = str(part["end"])
                if end < start:
                    raise ModelBundleVerificationError("split range is not chronological")
                if previous_end and start < previous_end:
                    raise ModelBundleVerificationError("split ranges are not chronological")
                previous_end = end
            ids.extend(str(item) for item in window_ids)
        if len(ids) != len(set(ids)):
            raise ModelBundleVerificationError("split window ids overlap")

    def _verify_registry_contract(
        self,
        registry: dict[str, Any],
        manifest: dict[str, Any],
        artifact_name: str,
        bundle_dir: Path,
    ) -> None:
        comparisons = {
            "family": manifest["family"],
            "model_version": manifest["model_version"],
            "dataset_id": manifest["dataset_id"],
            "dataset_manifest_sha256": manifest["dataset_manifest_sha256"],
            "dataset_kind": manifest["dataset_kind"],
            "profile_key": manifest["profile_key"],
            "feature_schema_version": manifest["feature_schema_version"],
            "split_id": manifest["split_id"],
            "threshold": manifest["threshold"],
        }
        for key, expected in comparisons.items():
            if registry[key] != expected:
                raise ModelBundleVerificationError(f"SQLite {key} mismatch")
        if registry["manifest_sha256"] != _sha_file(bundle_dir / "manifest.json"):
            raise ModelBundleVerificationError("SQLite manifest SHA-256 mismatch")
        if registry["model_artifact_sha256"] != _sha_file(bundle_dir / artifact_name):
            raise ModelBundleVerificationError("SQLite model artifact SHA-256 mismatch")

    def _verify_model_input_dimension(
        self,
        artifact: AutoencoderV2Model | IsolationForestV1Model,
        preprocessor: dict[str, Any],
    ) -> None:
        if int(artifact.input_dimension) != len(FEATURE_NAMES):
            raise ModelBundleVerificationError("model input dimension mismatch")
        if len(preprocessor["mean"]) != int(artifact.input_dimension):
            raise ModelBundleVerificationError("preprocessor/model dimension mismatch")

    def load(self, model_id: str) -> tuple[dict[str, Any], PreprocessorV1, Any]:
        self.verify(model_id)
        bundle_dir = self.bundle_dir(model_id)
        manifest = _read_json(bundle_dir / "manifest.json")
        family = str(manifest["family"])
        artifact_name = _artifact_name(family)
        preprocessor = PreprocessorV1(**_read_json(bundle_dir / "preprocessor.json"))
        return manifest, preprocessor, self._load_artifact(family, bundle_dir / artifact_name)

    def split_manifest(self, model_id: str) -> dict[str, Any]:
        self.verify(model_id)
        return _read_json(self.bundle_dir(model_id) / "split.json")

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
        self.data_dir = data_dir
        self.legacy_model_dir = model_dir
        self.models_dir = model_dir.parent / "models"
        self.compatibility = ModelCompatibilityService(storage, data_dir)
        self.verifier = ModelBundleVerifier(storage, self.models_dir, data_dir)

    def status(self) -> dict[str, Any]:
        models = self.storage.list_model_versions()
        legacy = self._legacy_unregistered_status(models)
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
            "legacy_unregistered": legacy["detected"],
            "legacy_artifact": legacy,
        }

    def _legacy_unregistered_status(self, models: list[dict[str, Any]]) -> dict[str, Any]:
        legacy_paths = [
            self.legacy_model_dir / "synthetic" / "model_info.json",
            self.legacy_model_dir / "synthetic" / "preprocessor.json",
            self.legacy_model_dir / "synthetic" / "autoencoder.pt",
        ]
        detected = all(path.exists() for path in legacy_paths)
        registered = any(
            str(model.get("artifact_path", "")).startswith(
                str((self.legacy_model_dir / "synthetic").resolve())
            )
            for model in models
        )
        return {
            "detected": detected and not registered,
            "description": (
                "legacy Stage 2 artifacts detected outside the Stage 3 SQLite registry"
                if detected and not registered
                else "no unregistered legacy Stage 2 model artifacts detected"
            ),
            "recommendation": "retrain with Stage 3" if detected and not registered else "none",
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
        if str(manifest["dataset_kind"]) != dataset_kind:
            raise ModelRegistryError("request dataset_kind does not match snapshot manifest")
        self._validate_training_eligibility(dataset_kind, manifest, rows)
        dataset_manifest_sha256 = str(manifest["verification"]["manifest_sha256"])
        selected_families = families or [
            ModelFamily.AUTOENCODER.value,
            ModelFamily.ISOLATION_FOREST.value,
        ]
        for family_value in selected_families:
            ModelFamily(family_value)
        training_run_id = f"train-{datetime.now(UTC).strftime('%Y%m%d%H%M%S')}-{uuid4().hex[:8]}"
        effective_config = {
            "families": selected_families,
            "target_fpr": target_fpr,
            "autoencoder": autoencoder_config or asdict(AutoencoderV2Config()),
            "isolation_forest": isolation_forest_config or asdict(IsolationForestV1Config()),
        }
        now = datetime.now(UTC).isoformat()
        self.storage.create_training_run_if_no_running(
            {
                "training_run_id": training_run_id,
                "dataset_id": dataset_id,
                "dataset_manifest_sha256": dataset_manifest_sha256,
                "dataset_kind": manifest["dataset_kind"],
                "profile_key": profile_key(manifest["profile"]),
                "split_id": "pending",
                "split_manifest_sha256": "pending",
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
        candidate_model_ids: list[str] = []
        created_bundle_dirs: list[Path] = []
        try:
            split = create_split_plan(
                rows,
                manifest,
                dataset_manifest_sha256=dataset_manifest_sha256,
            )
            self.storage.update_training_run_split(
                training_run_id,
                split_id=split.split_id,
                split_manifest_sha256=split.manifest_sha256,
            )
            train_matrix, calibration_matrix, test_matrix = split_matrices(rows, split)
            train_rows, calibration_rows, test_rows = split_rows(rows, split)
            preprocessor = PreprocessorV1.fit(train_matrix)
            scaled_train = preprocessor.transform(train_matrix)
            scaled_calibration = preprocessor.transform(calibration_matrix)
            scaled_test = preprocessor.transform(test_matrix)
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
                    train_rows=train_rows,
                    calibration_rows=calibration_rows,
                    test_rows=test_rows,
                    calibration_scores=calibration_scores,
                    scores=test_batch.scores,
                    threshold=calibration.threshold,
                    train_duration=train_duration,
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
                created_bundle_dirs.append(self.verifier.bundle_dir(model_id))
                bundle = self._create_bundle(
                    model_id=model_id,
                    model=model,
                    family=family,
                    manifest=manifest_payload,
                    dataset_manifest=manifest,
                    dataset_manifest_sha256=dataset_manifest_sha256,
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
                        "verified_at": None,
                    }
                )
                verification = self.verifier._verify_registered_pending(model_id)
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
                candidate_model_ids.append(model_id)
            finalized_at = datetime.now(UTC).isoformat()
            self.storage.finalize_training_run_success(
                training_run_id,
                model_ids=candidate_model_ids,
                completed_at=finalized_at,
                verified_at=finalized_at,
            )
            for candidate in candidates:
                candidate["verification"] = self.verifier.verify(str(candidate["model_id"]))
            result_payload: dict[str, Any] = {
                "training_run_id": training_run_id,
                "dataset_id": dataset_id,
                "dataset_manifest_sha256": dataset_manifest_sha256,
                "split": split.to_manifest(),
                "candidates": candidates,
                "recommended_model_id": None,
            }
        except Exception as exc:
            self.storage.delete_models_for_training_run(training_run_id)
            for path in created_bundle_dirs:
                if path.exists():
                    shutil.rmtree(path)
            self.storage.complete_training_run(
                training_run_id,
                status="failed",
                completed_at=datetime.now(UTC).isoformat(),
                error_class=type(exc).__name__,
                safe_error_message=_safe_error(exc),
            )
            raise
        try:
            recommended = self._recommend(candidates, manifest["dataset_kind"])
            if recommended is not None:
                self.storage.update_model_lifecycle(
                    str(recommended["model_id"]),
                    LifecycleStatus.RECOMMENDED.value,
                )
                result_payload["recommended_model_id"] = recommended["model_id"]
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
        except Exception as exc:  # noqa: BLE001
            result_payload["lifecycle_warning"] = _safe_error(exc)
        return result_payload

    def _validate_training_eligibility(
        self,
        dataset_kind: str,
        manifest: dict[str, Any],
        rows: list[dict[str, Any]],
    ) -> None:
        if dataset_kind != "real":
            return
        eligibility = EligibilityService(self.storage).training_eligibility("real")
        if not bool(eligibility["eligible"]):
            raise ModelRegistryError(f"real training not eligible: {eligibility['reason']}")
        if float(cast(float, eligibility.get("usable_coverage_hours", 0.0))) < 24:
            raise ModelRegistryError("real training requires at least 24 usable hours")
        if int(cast(int, eligibility.get("good_windows", 0))) < 96:
            raise ModelRegistryError("real training requires at least 96 good windows")
        if manifest.get("dataset_kind") != "real":
            raise ModelRegistryError("real training requires a real snapshot")
        if manifest.get("feature_schema_version") != FEATURE_SCHEMA_VERSION:
            raise ModelRegistryError("real snapshot feature schema is incompatible")
        profiles = {(row.get("user_id"), row.get("host_id")) for row in rows}
        if len(profiles) != 1:
            raise ModelRegistryError("real snapshot must contain exactly one profile")
        only_profile = next(iter(profiles))
        if manifest.get("profile") != {"user_id": only_profile[0], "host_id": only_profile[1]}:
            raise ModelRegistryError("real snapshot profile does not match rows")
        if any(row.get("dataset_kind") != "real" for row in rows):
            raise ModelRegistryError("real snapshot contains non-real rows")
        if any(row.get("quality_status") != "good" for row in rows):
            raise ModelRegistryError("real snapshot contains non-good windows")
        if len(rows) < 96:
            raise ModelRegistryError("real snapshot requires at least 96 good windows")
        if manifest.get("quality_filters") != ["good"]:
            raise ModelRegistryError("real snapshot must be filtered to good windows")
        start = datetime.fromisoformat(str(manifest["start"]))
        end = datetime.fromisoformat(str(manifest["end"]))
        if (end - start).total_seconds() < 24 * 60 * 60:
            raise ModelRegistryError("real snapshot requires at least 24 hours of coverage")
        if float(cast(float, eligibility["cumulative_collected_seconds"])) < float(
            cast(float, eligibility["usable_coverage_seconds"])
        ):
            raise ModelRegistryError("real cumulative duration is less than usable coverage")

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
            "compatibility": self.compatibility.verify_source(model_id),
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
        return self._promote_checked(model_id, reason=reason, action="promote")

    def recommend(
        self,
        model_id: str,
        *,
        confirm: bool,
        reason: str = "manual recommendation",
    ) -> dict[str, Any]:
        if not confirm:
            raise ModelRegistryError("recommendation requires confirmation")
        model = self.storage.get_model_version(model_id)
        if model is None:
            raise ModelRegistryError("model is not registered")
        self.verify_model(model_id)
        if model["lifecycle_status"] != LifecycleStatus.CANDIDATE.value:
            raise ModelRegistryError("only candidate models can be recommended")
        if self.storage.latest_model_evaluation(model_id) is None:
            raise ModelRegistryError("model evaluation is required before promotion")
        self.compatibility.verify_source(model_id)
        self.storage.update_model_lifecycle(
            model_id,
            LifecycleStatus.RECOMMENDED.value,
            verified_at=datetime.now(UTC).isoformat(),
        )
        return {"model_id": model_id, "action": "recommend", "reason": reason}

    def _promote_checked(self, model_id: str, *, reason: str, action: str) -> dict[str, Any]:
        model = self.storage.get_model_version(model_id)
        if model is None:
            raise ModelRegistryError("model is not registered")
        status = str(model["lifecycle_status"])
        if action == "rollback":
            if status != LifecycleStatus.RETIRED.value:
                raise ModelRegistryError("rollback is allowed only for retired models")
        elif status not in {LifecycleStatus.CANDIDATE.value, LifecycleStatus.RECOMMENDED.value}:
            if status == LifecycleStatus.CHAMPION.value:
                raise ModelRegistryError("model is already champion")
            raise ModelRegistryError(f"{status} model cannot be promoted")
        self.verify_model(model_id)
        self.compatibility.verify_source(model_id)
        if self.storage.latest_model_evaluation(model_id) is None:
            raise ModelRegistryError("model evaluation is required before promotion")
        return self.storage.promote_model(
            promotion_id=f"promotion-{uuid4().hex[:12]}",
            model_id=model_id,
            action=action,
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
        model = self.storage.get_model_version(model_id)
        if model is None:
            raise ModelRegistryError("model is not registered")
        if model["lifecycle_status"] != LifecycleStatus.CHAMPION.value:
            raise ModelRegistryError("only champion models can be retired")
        self.verify_model(model_id)
        self.compatibility.verify_source(model_id)
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
        return self._promote_checked(model_id, reason=reason, action="rollback")

    def score(
        self,
        *,
        dataset_id: str,
        model_id: str | None = None,
        dataset_kind: str | None = None,
        sync_anomalies: bool = False,
        batch_size: int = 256,
    ) -> dict[str, Any]:
        matrix, manifest, rows = self.snapshots.load_matrix(dataset_id)
        if model_id is None:
            champion = self.storage.champion_model(
                str(dataset_kind or manifest["dataset_kind"]),
                profile_key(manifest["profile"]),
            )
            if champion is None:
                raise ModelRegistryError("champion model is not available")
            model_id = str(champion["model_id"])
        started = datetime.now(UTC)
        scoring_run_id = f"score-{datetime.now(UTC).strftime('%Y%m%d%H%M%S')}-{uuid4().hex[:8]}"
        self.storage.create_scoring_run_start(
            {
                "scoring_run_id": scoring_run_id,
                "model_id": model_id,
                "dataset_id": dataset_id,
                "dataset_manifest_sha256": manifest["verification"]["manifest_sha256"],
                "split_range": {"kind": "full_snapshot"},
                "started_at": started.isoformat(),
                "threshold": 0.0,
            }
        )
        try:
            compatibility = self._assert_scoring_compatible(model_id, dataset_id)
            model_record = compatibility["model"]
            model_manifest, preprocessor, model = self.verifier.load(model_id)
            if model_manifest["feature_names"] != FEATURE_NAMES:
                raise ModelRegistryError("feature names/order mismatch")
            threshold = float(model_manifest["threshold"])
            explanation_kind = str(model_manifest["explanation_kind"])
            safe_batch_size = max(1, min(int(batch_size), 4096))
            scored: list[dict[str, Any]] = []
            anomalies: list[AnomalyRecord] = []
            for start in range(0, len(rows), safe_batch_size):
                batch_rows = rows[start : start + safe_batch_size]
                raw_batch = matrix[start : start + safe_batch_size]
                scaled_batch = preprocessor.transform(raw_batch)
                score_batch = model.score(scaled_batch)
                if model_manifest["family"] == ModelFamily.AUTOENCODER.value:
                    explanations = model.residual_contributions(
                        scaled_batch,
                        FEATURE_NAMES,
                        raw_batch,
                        preprocessor,
                    )
                else:
                    explanations = [preprocessor.context_deviations(row) for row in raw_batch]
                for row, score, explanation in zip(
                    batch_rows,
                    score_batch.scores,
                    explanations,
                    strict=True,
                ):
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
                                top_features=[
                                    str(item["feature_name"]) for item in explanation[:3]
                                ],
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
            self.storage.complete_scoring_run_success(
                scoring_run_id,
                threshold=threshold,
                completed_at=datetime.now(UTC).isoformat(),
                rows=scored,
            )
            if sync_anomalies:
                self.storage.replace_anomalies(anomalies)
            return {
                "scoring_run_id": scoring_run_id,
                "model_id": model_id,
                "dataset_id": dataset_id,
                "window_count": len(rows),
                "anomaly_count": len(anomalies),
                "batch_size": safe_batch_size,
                "split_range": {"kind": "full_snapshot"},
                "top_anomalies": sorted(
                    scored,
                    key=lambda item: item["anomaly_score"],
                    reverse=True,
                )[:5],
                "compatibility": {
                    "status": "ok",
                    "source_dataset_id": model_record["dataset_id"],
                    "target_dataset_id": dataset_id,
                    "feature_schema_version": FEATURE_SCHEMA_VERSION,
                },
            }
        except Exception as exc:
            self.storage.complete_scoring_run_failed(
                scoring_run_id,
                completed_at=datetime.now(UTC).isoformat(),
                safe_error=_safe_error(exc),
            )
            raise

    def _assert_scoring_compatible(
        self,
        model_id: str,
        dataset_id: str,
    ) -> dict[str, Any]:
        compatibility = self.compatibility.verify_target(model_id, dataset_id)
        self.verify_model(model_id)
        return compatibility

    def evaluate(self, model_id: str) -> dict[str, Any]:
        model = self.storage.get_model_version(model_id)
        if model is None:
            raise ModelRegistryError("model is not registered")
        return self.storage.latest_model_evaluation(model_id) or {}

    def compare(self, model_ids: list[str]) -> dict[str, Any]:
        reports: list[dict[str, Any]] = []
        compatibility_keys: list[tuple[Any, ...]] = []
        pairwise_failures: list[dict[str, Any]] = []
        for model_id in model_ids:
            model = self.storage.get_model_version(model_id)
            if model is None:
                reports.append(
                    {
                        "model_id": model_id,
                        "verification_status": "missing",
                        "compatibility": {"status": "failed", "reason": "model is not registered"},
                    }
                )
                continue
            verification_status = "ok"
            compatibility_status: dict[str, Any]
            feature_order: list[str] | None = None
            try:
                compatibility_status = self.compatibility.verify_source(model_id)
                verification = self.verify_model(model_id)
                bundle_manifest = _read_json(self.verifier.bundle_dir(model_id) / "manifest.json")
                feature_order = cast(list[str], bundle_manifest.get("feature_names"))
            except Exception as exc:  # noqa: BLE001
                verification_status = "failed"
                compatibility_status = {"status": "failed", "reason": _safe_error(exc)}
                verification = {"verified": False}
            evaluation = self.storage.latest_model_evaluation(model_id) or {}
            metrics = evaluation.get("metrics", {}) if evaluation else {}
            compatibility_keys.append(
                (
                    model["dataset_kind"],
                    model["profile_key"],
                    model["feature_schema_version"],
                    tuple(feature_order or []),
                    model["dataset_id"],
                    model["split_id"],
                )
            )
            reports.append(
                {
                    "model_id": model_id,
                    "family": model["family"],
                    "model_version": model["model_version"],
                    "dataset_id": model["dataset_id"],
                    "dataset_kind": model["dataset_kind"],
                    "split_id": model["split_id"],
                    "threshold": model["threshold"],
                    "lifecycle_status": model["lifecycle_status"],
                    "verification_status": verification_status,
                    "compatibility": {"status": compatibility_status.get("status", "ok")},
                    "verified": bool(verification.get("verified")),
                    "label_status": metrics.get("label_status"),
                    "scenario_recall": metrics.get("scenario_recall"),
                    "false_positive_rate": metrics.get("false_positive_rate"),
                    "pr_auc": metrics.get("pr_auc"),
                    "precision": metrics.get("precision"),
                    "recall": metrics.get("recall"),
                    "f1": metrics.get("f1"),
                    "training_duration_seconds": metrics.get("training_duration_seconds"),
                    "inference_duration_seconds": metrics.get("inference_duration_seconds"),
                }
            )
        for left_index, left_key in enumerate(compatibility_keys):
            for right_index, right_key in enumerate(
                compatibility_keys[left_index + 1 :],
                start=left_index + 1,
            ):
                if left_key != right_key:
                    pairwise_failures.append(
                        {
                            "left_model_id": reports[left_index]["model_id"],
                            "right_model_id": reports[right_index]["model_id"],
                            "status": "failed",
                            "reason": (
                                "models use different dataset, split, profile, schema, "
                                "or feature order"
                            ),
                        }
                    )
        synthetic = [
            item
            for item in reports
            if item.get("dataset_kind") == "synthetic" and item.get("verification_status") == "ok"
        ]
        can_recommend = (
            bool(synthetic)
            and len(synthetic) == len(reports)
            and not pairwise_failures
        )
        ordering = [
            item["model_id"]
            for item in sorted(
                synthetic,
                key=lambda item: (
                    _metric_value(item.get("scenario_recall"), default=0.0),
                    -_metric_value(item.get("false_positive_rate"), default=1.0),
                    _metric_value(item.get("pr_auc"), default=0.0),
                    -_metric_value(item.get("inference_duration_seconds"), default=float("inf")),
                ),
                reverse=True,
            )
        ] if can_recommend else []
        return {
            "models": reports,
            "pairwise_compatibility": (
                pairwise_failures if pairwise_failures else [{"status": "ok"}]
            ),
            "recommendation_order": ordering,
        }

    def drift(self, *, model_id: str, dataset_id: str) -> dict[str, Any]:
        compatibility = self.compatibility.verify_target(model_id, dataset_id)
        model_record = compatibility["model"]
        model_manifest, preprocessor, model = self.verifier.load(model_id)
        _, _, source_rows = self.snapshots.load_matrix(str(model_record["dataset_id"]))
        target_matrix, _, target_rows = self.snapshots.load_matrix(dataset_id)
        split = self.verifier.split_manifest(model_id)
        train_ids = {str(item) for item in split["train"]["window_ids"]}
        train_rows = [row for row in source_rows if str(row["window_id"]) in train_ids]
        if len(train_rows) < 12 or len(target_rows) < 12:
            return {"status": "insufficient_data", "compatibility": {"status": "ok"}}
        train_matrix = [[float(row[name]) for name in FEATURE_NAMES] for row in train_rows]
        train = np.asarray(train_matrix, dtype=np.float64)
        target = np.asarray([[float(row[name]) for name in FEATURE_NAMES] for row in target_rows])
        if not np.isfinite(train).all() or not np.isfinite(target).all():
            raise ModelRegistryError("drift input contains NaN or Infinity")
        reference_scores = model.score(preprocessor.transform(train_matrix)).scores
        target_scores = []
        for start in range(0, len(target_matrix), 256):
            target_scores.extend(
                model.score(preprocessor.transform(target_matrix[start : start + 256])).scores
            )
        threshold = float(model_manifest["threshold"])
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
            "reference_split": {"kind": "train", "count": len(train_rows)},
            "model_score_quantiles": {
                "reference": _percentiles(reference_scores),
                "target": _percentiles(target_scores),
            },
            "reference_flagged_rate": _flagged_rate(reference_scores, threshold),
            "target_flagged_rate": _flagged_rate(target_scores, threshold),
            "flagged_rate_difference": _flagged_rate(target_scores, threshold)
            - _flagged_rate(reference_scores, threshold),
            "compatibility": {"status": "ok", "source_dataset_id": model_record["dataset_id"]},
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
        train_rows: list[dict[str, Any]],
        calibration_rows: list[dict[str, Any]],
        test_rows: list[dict[str, Any]],
        calibration_scores: list[float],
        scores: list[float],
        threshold: float,
        train_duration: float,
        inference_duration: float,
    ) -> dict[str, Any]:
        flagged = [score >= threshold for score in scores]
        calibration_flagged = [score >= threshold for score in calibration_scores]
        base: dict[str, Any] = {
            "label_status": "unlabeled" if manifest["dataset_kind"] == "real" else "labeled",
            "train_count": split.train.count,
            "calibration_count": split.calibration.count,
            "test_count": split.test.count,
            "split_ranges": {
                "train": _range_payload(train_rows),
                "calibration": _range_payload(calibration_rows),
                "test": _range_payload(test_rows),
            },
            "threshold": threshold,
            "calibration_flagged_rate": (
                sum(calibration_flagged) / len(calibration_flagged) if calibration_flagged else 0.0
            ),
            "calibration_score_percentiles": _percentiles(calibration_scores),
            "flagged_window_rate": sum(flagged) / len(flagged) if flagged else 0.0,
            "score_percentiles": _percentiles(scores),
            "top_scoring_windows": _top_scoring_windows(test_rows, scores, limit=5),
            "training_duration_seconds": train_duration,
            "inference_duration_seconds": inference_duration,
            "windows_per_second": len(scores) / max(inference_duration, 1e-9),
        }
        if manifest["dataset_kind"] == "real":
            base.update(
                {
                    "test_flagged_rate": base["flagged_window_rate"],
                    "feature_distribution_summary": _feature_distribution_summary(test_rows),
                    "stability_summary": _stability_summary(calibration_scores, scores, threshold),
                    "limitations": [
                        "real data is unlabeled",
                        "accuracy, precision, recall, F1, ROC-AUC and PR-AUC are not reported",
                    ],
                }
            )
            return base
        positives = set(split.scenario_window_ids)
        labels = [str(row["window_id"]) in positives for row in test_rows]
        scenario_by_start = {
            item["window_start"]: item["name"]
            for item in scenario_manifest_for_start(datetime.fromisoformat(str(manifest["start"])))
        }
        detected_names = {
            scenario_by_start.get(str(row["window_start"]), str(row["window_id"]))
            for row, mark in zip(test_rows, flagged, strict=True)
            if str(row["window_id"]) in positives and mark
        }
        missed_names = {
            scenario_by_start.get(str(row["window_start"]), str(row["window_id"]))
            for row, mark in zip(test_rows, flagged, strict=True)
            if str(row["window_id"]) in positives and not mark
        }
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
                "detected_scenario_names": sorted(detected_names),
                "missed_scenario_names": sorted(missed_names),
                "test_normal_count": normal_count,
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
        dataset_manifest: dict[str, Any],
        dataset_manifest_sha256: str,
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
            self.verifier.verify_internal(
                model_id,
                tmp_dir,
                expected_dataset_manifest=dataset_manifest,
                expected_dataset_manifest_sha256=dataset_manifest_sha256,
            )
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
    if family == ModelFamily.AUTOENCODER.value:
        return "autoencoder.pt"
    if family == ModelFamily.ISOLATION_FOREST.value:
        return "isolation_forest.skops"
    raise ModelBundleVerificationError("unsupported model family")


def _split_manifest_sha256(split: dict[str, Any]) -> str:
    payload = {
        key: value
        for key, value in split.items()
        if key not in {"manifest_sha256", "split_id"}
    }
    return _sha_json(payload)


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


def _safe_error(exc: Exception) -> str:
    message = str(exc).replace(str(Path.home()), "~")
    for marker in ["Traceback", "\n  File ", "payload", "secret"]:
        message = message.replace(marker, "[redacted]")
    return message[:500]


def _range_payload(rows: list[dict[str, Any]]) -> dict[str, Any]:
    if not rows:
        return {"count": 0, "start": None, "end": None}
    return {
        "count": len(rows),
        "start": rows[0]["window_start"],
        "end": rows[-1]["window_end"],
    }


def _top_scoring_windows(
    rows: list[dict[str, Any]],
    scores: list[float],
    *,
    limit: int,
) -> list[dict[str, Any]]:
    ranked = sorted(
        zip(rows, scores, strict=True),
        key=lambda item: float(item[1]),
        reverse=True,
    )[:limit]
    return [
        {
            "window_id": str(row["window_id"]),
            "window_start": str(row["window_start"]),
            "window_end": str(row["window_end"]),
            "score": float(score),
        }
        for row, score in ranked
    ]


def _feature_distribution_summary(
    rows: list[dict[str, Any]],
    limit: int = 5,
) -> list[dict[str, Any]]:
    if not rows:
        return []
    matrix = np.asarray([[float(row[name]) for name in FEATURE_NAMES] for row in rows])
    summaries: list[dict[str, Any]] = []
    for index, name in enumerate(FEATURE_NAMES):
        values = matrix[:, index]
        summaries.append(
            {
                "feature_name": name,
                "mean": float(np.mean(values)),
                "std": float(np.std(values)),
                "quantiles": _percentiles(values.tolist()),
            }
        )
    return sorted(summaries, key=lambda item: abs(float(item["std"])), reverse=True)[:limit]


def _stability_summary(
    calibration_scores: list[float],
    test_scores: list[float],
    threshold: float,
) -> dict[str, float]:
    return {
        "calibration_flagged_rate": _flagged_rate(calibration_scores, threshold),
        "test_flagged_rate": _flagged_rate(test_scores, threshold),
        "flagged_rate_difference": _flagged_rate(test_scores, threshold)
        - _flagged_rate(calibration_scores, threshold),
    }


def _flagged_rate(scores: list[float], threshold: float) -> float:
    return sum(1 for score in scores if float(score) >= threshold) / len(scores) if scores else 0.0


def _metric_value(value: object, *, default: float) -> float:
    if value is None:
        return default
    return float(cast(float, value))


def _percentiles(scores: list[float]) -> dict[str, float]:
    if not scores:
        return {}
    values = np.asarray(scores, dtype=np.float64)
    if not np.isfinite(values).all():
        raise ModelRegistryError("score contains NaN or Infinity")
    return {
        "p05": float(np.percentile(values, 5)),
        "p50": float(np.percentile(values, 50)),
        "p95": float(np.percentile(values, 95)),
        "p99": float(np.percentile(values, 99)),
    }


def _psi(expected: np.ndarray, actual: np.ndarray, buckets: int = 10) -> float:
    expected = np.asarray(expected, dtype=np.float64)
    actual = np.asarray(actual, dtype=np.float64)
    if not np.isfinite(expected).all() or not np.isfinite(actual).all():
        raise ModelRegistryError("PSI input contains NaN or Infinity")
    if expected.size == 0 or actual.size == 0:
        return 0.0
    if np.ptp(expected) < 1e-12:
        center = float(expected[0])
        if np.ptp(actual) < 1e-12 and abs(float(actual[0]) - center) < 1e-12:
            return 0.0
        spread = max(abs(center) * 1e-6, 1e-6)
        quantiles = np.asarray([center - spread, center + spread], dtype=np.float64)
    else:
        quantiles = np.unique(np.percentile(expected, np.linspace(0, 100, buckets + 1)))
        if quantiles.size < 2:
            return 0.0
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
