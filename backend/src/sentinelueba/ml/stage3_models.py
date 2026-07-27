from __future__ import annotations

import json
import random
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, cast

import numpy as np
import skops.io as sio
import torch
from sklearn.ensemble import IsolationForest
from torch import nn

from sentinelueba.ml.stage3_contracts import ModelFamily, ModelScoreBatch, PreprocessorV1

AUTOENCODER_V2 = "autoencoder-v2"
ISOLATION_FOREST_V1 = "isolation-forest-v1"


class ModelTrainingError(ValueError):
    pass


@dataclass(frozen=True)
class AutoencoderV2Config:
    epochs: int = 80
    batch_size: int = 16
    learning_rate: float = 0.005
    weight_decay: float = 0.0001
    hidden_dim: int = 10
    latent_dim: int = 4
    max_epochs: int = 300
    plateau_patience: int = 12


class AutoencoderNetwork(nn.Module):
    def __init__(self, input_dim: int, hidden_dim: int, latent_dim: int) -> None:
        super().__init__()
        self.net = nn.Sequential(
            nn.Linear(input_dim, hidden_dim),
            nn.ReLU(),
            nn.Linear(hidden_dim, latent_dim),
            nn.ReLU(),
            nn.Linear(latent_dim, hidden_dim),
            nn.ReLU(),
            nn.Linear(hidden_dim, input_dim),
        )

    def forward(self, value: torch.Tensor) -> torch.Tensor:
        return cast(torch.Tensor, self.net(value))


class AutoencoderV2Model:
    family = ModelFamily.AUTOENCODER
    version = AUTOENCODER_V2

    def __init__(self, config: AutoencoderV2Config | None = None) -> None:
        self.config = config or AutoencoderV2Config()
        self.model: AutoencoderNetwork | None = None
        self.loss_history: list[float] = []

    def fit(self, matrix: list[list[float]], *, seed: int) -> None:
        if self.config.epochs > self.config.max_epochs:
            raise ModelTrainingError("autoencoder epochs exceed configured safety limit")
        _set_seed(seed)
        data = np.asarray(matrix, dtype=np.float32)
        if data.ndim != 2 or data.shape[0] < 1:
            raise ModelTrainingError("train matrix is empty")
        if not np.isfinite(data).all():
            raise ModelTrainingError("train matrix contains NaN or Infinity")
        self.model = AutoencoderNetwork(
            data.shape[1],
            max(2, self.config.hidden_dim),
            max(1, self.config.latent_dim),
        )
        optimizer = torch.optim.Adam(
            self.model.parameters(),
            lr=self.config.learning_rate,
            weight_decay=self.config.weight_decay,
        )
        loss_fn = nn.MSELoss()
        tensor = torch.tensor(data, dtype=torch.float32)
        best = float("inf")
        stale = 0
        for _ in range(self.config.epochs):
            epoch_losses: list[float] = []
            for start in range(0, len(tensor), self.config.batch_size):
                batch = tensor[start : start + self.config.batch_size]
                optimizer.zero_grad()
                output = self.model(batch)
                loss = loss_fn(output, batch)
                if not torch.isfinite(loss):
                    raise ModelTrainingError("autoencoder training diverged")
                loss.backward()
                optimizer.step()
                epoch_losses.append(float(loss.detach().item()))
            current = float(np.mean(epoch_losses))
            if not np.isfinite(current):
                raise ModelTrainingError("autoencoder training produced non-finite loss")
            self.loss_history.append(current)
            if current < best - 1e-7:
                best = current
                stale = 0
            else:
                stale += 1
            if stale >= self.config.plateau_patience:
                break

    def score(self, matrix: list[list[float]]) -> ModelScoreBatch:
        if self.model is None:
            raise ModelTrainingError("autoencoder is not fitted")
        data = np.asarray(matrix, dtype=np.float32)
        with torch.no_grad():
            tensor = torch.tensor(data, dtype=torch.float32)
            reconstructed = self.model(tensor)
            residuals = (reconstructed - tensor) ** 2
            scores = torch.mean(residuals, dim=1).numpy().astype(float).tolist()
        explanations = []
        for residual_row in residuals.numpy():
            pairs = [
                {
                    "feature_name": f"feature_{index}",
                    "contribution": float(value),
                }
                for index, value in enumerate(residual_row)
            ]
            explanations.append(
                sorted(
                    pairs,
                    key=lambda item: cast(float, item["contribution"]),
                    reverse=True,
                )
            )
        return ModelScoreBatch(
            scores=scores,
            explanations=explanations,
            explanation_kind="autoencoder_reconstruction_contribution",
        )

    def residual_contributions(
        self,
        matrix: list[list[float]],
        feature_names: list[str],
        raw_matrix: list[list[float]],
        preprocessor: PreprocessorV1,
        limit: int = 5,
    ) -> list[list[dict[str, object]]]:
        if self.model is None:
            raise ModelTrainingError("autoencoder is not fitted")
        data = np.asarray(matrix, dtype=np.float32)
        raw = np.asarray(raw_matrix, dtype=np.float32)
        mean = np.asarray(preprocessor.mean, dtype=np.float32)
        std = np.asarray(preprocessor.std, dtype=np.float32)
        with torch.no_grad():
            tensor = torch.tensor(data, dtype=torch.float32)
            reconstructed_scaled = self.model(tensor).numpy()
            residuals = ((reconstructed_scaled - data) ** 2).astype(float)
        reconstructed_raw = reconstructed_scaled * std + mean
        all_rows = []
        for raw_row, expected_row, residual_row in zip(
            raw,
            reconstructed_raw,
            residuals,
            strict=True,
        ):
            row = []
            for index, name in enumerate(feature_names):
                observed = float(raw_row[index])
                expected = float(expected_row[index])
                row.append(
                    {
                        "feature_name": name,
                        "observed_value": observed,
                        "expected_value": expected,
                        "contribution": float(residual_row[index]),
                        "direction": "above" if observed > expected else "below",
                    }
                )
            all_rows.append(
                sorted(
                    row,
                    key=lambda item: cast(float, item["contribution"]),
                    reverse=True,
                )[:limit]
            )
        return all_rows

    def save_artifact(self, path: Path) -> None:
        if self.model is None:
            raise ModelTrainingError("autoencoder is not fitted")
        torch.save(
            {
                "state_dict": self.model.state_dict(),
                "config": asdict(self.config),
                "loss_history": self.loss_history,
            },
            path,
        )

    @classmethod
    def load_verified_artifact(cls, path: Path) -> AutoencoderV2Model:
        payload = torch.load(path, map_location="cpu", weights_only=True)
        config = AutoencoderV2Config(**payload["config"])
        model = cls(config)
        state_dict = payload["state_dict"]
        first_weight = next(iter(state_dict.values()))
        input_dim = int(first_weight.shape[1])
        model.model = AutoencoderNetwork(input_dim, config.hidden_dim, config.latent_dim)
        model.model.load_state_dict(state_dict)
        model.model.eval()
        model.loss_history = [float(value) for value in payload.get("loss_history", [])]
        return model


@dataclass(frozen=True)
class IsolationForestV1Config:
    n_estimators: int = 80
    max_samples: str | int | float = "auto"
    max_features: float = 1.0
    bootstrap: bool = False
    n_jobs: int = 1


class IsolationForestV1Model:
    family = ModelFamily.ISOLATION_FOREST
    version = ISOLATION_FOREST_V1

    def __init__(self, config: IsolationForestV1Config | None = None) -> None:
        self.config = config or IsolationForestV1Config()
        self.model: IsolationForest | None = None

    def fit(self, matrix: list[list[float]], *, seed: int) -> None:
        data = np.asarray(matrix, dtype=np.float32)
        if data.ndim != 2 or data.shape[0] < 1:
            raise ModelTrainingError("train matrix is empty")
        if not np.isfinite(data).all():
            raise ModelTrainingError("train matrix contains NaN or Infinity")
        self.model = IsolationForest(
            n_estimators=self.config.n_estimators,
            max_samples=self.config.max_samples,
            max_features=self.config.max_features,
            bootstrap=self.config.bootstrap,
            contamination="auto",
            n_jobs=max(1, min(int(self.config.n_jobs), 2)),
            random_state=seed,
        )
        self.model.fit(data)

    def score(self, matrix: list[list[float]]) -> ModelScoreBatch:
        if self.model is None:
            raise ModelTrainingError("isolation forest is not fitted")
        data = np.asarray(matrix, dtype=np.float32)
        scores = (-self.model.score_samples(data)).astype(float).tolist()
        return ModelScoreBatch(
            scores=scores,
            explanations=[],
            explanation_kind="isolation_forest_context_deviation",
        )

    def save_artifact(self, path: Path) -> None:
        if self.model is None:
            raise ModelTrainingError("isolation forest is not fitted")
        sio.dump(self.model, path)

    @classmethod
    def load_verified_artifact(cls, path: Path) -> IsolationForestV1Model:
        unknown = sio.get_untrusted_types(file=path)
        allowed = {
            "sklearn.ensemble._iforest.IsolationForest",
            "sklearn.tree._classes.ExtraTreeRegressor",
            "sklearn.tree._tree.Tree",
            "sklearn.tree._tree.TreeBuilder",
            "numpy.ndarray",
            "numpy.dtype",
        }
        if any(item not in allowed for item in unknown):
            raise ModelTrainingError("untrusted estimator type in skops artifact")
        loaded = sio.load(path, trusted=unknown)
        if not isinstance(loaded, IsolationForest):
            raise ModelTrainingError("expected IsolationForest artifact")
        model = cls()
        model.model = loaded
        return model


def model_from_family(
    family: ModelFamily,
    parameters: dict[str, Any],
) -> AutoencoderV2Model | IsolationForestV1Model:
    if family == ModelFamily.AUTOENCODER:
        return AutoencoderV2Model(AutoencoderV2Config(**parameters))
    if family == ModelFamily.ISOLATION_FOREST:
        return IsolationForestV1Model(IsolationForestV1Config(**parameters))
    raise ModelTrainingError(f"unsupported model family: {family}")


def _set_seed(seed: int) -> None:
    random.seed(seed)
    np.random.seed(seed)
    torch.manual_seed(seed)
    torch.use_deterministic_algorithms(False)


def effective_config_json(family: ModelFamily, parameters: dict[str, Any], seed: int) -> str:
    payload = {"family": family.value, "seed": seed, "parameters": parameters}
    return json.dumps(payload, sort_keys=True)
