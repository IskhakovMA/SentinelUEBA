from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum
from pathlib import Path
from typing import Protocol, cast

from sentinelueba.features.windows import FEATURE_NAMES, FEATURE_SCHEMA_VERSION


class ModelFamily(StrEnum):
    AUTOENCODER = "autoencoder"
    ISOLATION_FOREST = "isolation-forest"


class LifecycleStatus(StrEnum):
    CANDIDATE = "candidate"
    RECOMMENDED = "recommended"
    CHAMPION = "champion"
    RETIRED = "retired"
    REJECTED = "rejected"
    FAILED = "failed"


@dataclass(frozen=True)
class ModelConfig:
    family: ModelFamily
    version: str
    seed: int = 42
    parameters: dict[str, object] = field(default_factory=dict)


@dataclass(frozen=True)
class PreprocessorV1:
    feature_names: list[str]
    mean: list[float]
    std: list[float]
    median: list[float]
    iqr: list[float]
    feature_schema_version: str = FEATURE_SCHEMA_VERSION
    version: str = "preprocessor-v1"

    @classmethod
    def fit(cls, matrix: list[list[float]]) -> PreprocessorV1:
        import numpy as np

        if not matrix:
            raise ValueError("train split is empty")
        data = np.asarray(matrix, dtype=np.float32)
        if not np.isfinite(data).all():
            raise ValueError("feature matrix contains NaN or Infinity")
        mean = data.mean(axis=0)
        std = data.std(axis=0)
        std[std < 1e-6] = 1.0
        median = np.median(data, axis=0)
        q75 = np.percentile(data, 75, axis=0)
        q25 = np.percentile(data, 25, axis=0)
        iqr = q75 - q25
        iqr[iqr < 1e-6] = 1.0
        return cls(
            feature_names=FEATURE_NAMES.copy(),
            mean=mean.astype(float).tolist(),
            std=std.astype(float).tolist(),
            median=median.astype(float).tolist(),
            iqr=iqr.astype(float).tolist(),
        )

    def transform(self, matrix: list[list[float]]) -> list[list[float]]:
        import numpy as np

        data = np.asarray(matrix, dtype=np.float32)
        if not np.isfinite(data).all():
            raise ValueError("feature matrix contains NaN or Infinity")
        mean = np.asarray(self.mean, dtype=np.float32)
        std = np.asarray(self.std, dtype=np.float32)
        return cast(list[list[float]], ((data - mean) / std).astype(float).tolist())

    def context_deviations(self, row: list[float], limit: int = 5) -> list[dict[str, object]]:
        pairs = []
        for index, name in enumerate(self.feature_names):
            observed = float(row[index])
            median = float(self.median[index])
            deviation = (observed - median) / max(float(self.iqr[index]), 1e-9)
            pairs.append(
                {
                    "feature_name": name,
                    "observed_value": observed,
                    "train_median": median,
                    "context_deviation": float(deviation),
                    "direction": "above" if deviation > 0 else "below",
                }
            )
        return sorted(
            pairs,
            key=lambda item: abs(cast(float, item["context_deviation"])),
            reverse=True,
        )[:limit]


@dataclass(frozen=True)
class TrainedModel:
    model_id: str
    family: ModelFamily
    version: str
    threshold: float
    feature_names: list[str]
    feature_schema_version: str
    dataset_id: str
    dataset_manifest_sha256: str
    dataset_kind: str
    profile: dict[str, str]
    split_id: str
    bundle_dir: Path


@dataclass(frozen=True)
class ModelScoreBatch:
    scores: list[float]
    explanations: list[list[dict[str, object]]]
    explanation_kind: str


class AnomalyModel(Protocol):
    family: ModelFamily
    version: str

    def fit(self, matrix: list[list[float]], *, seed: int) -> None:
        """Fit on train-only, preprocessed matrix."""

    def score(self, matrix: list[list[float]]) -> ModelScoreBatch:
        """Return anomaly scores where higher means more anomalous."""

    def save_artifact(self, path: Path) -> None:
        """Write the model artifact."""

    @classmethod
    def load_verified_artifact(cls, path: Path) -> AnomalyModel:
        """Load a verified model artifact."""
