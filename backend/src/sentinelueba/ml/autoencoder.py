from __future__ import annotations

import hashlib
import json
import random
from dataclasses import asdict, dataclass
from datetime import UTC, datetime
from importlib.metadata import version
from pathlib import Path
from typing import cast

import numpy as np
import torch
from torch import nn

from sentinelueba.features.windows import FEATURE_NAMES

MODEL_VERSION = "autoencoder-stage1-v1"
FEATURE_SCHEMA_VERSION = "feature-windows-v1"


@dataclass(frozen=True)
class Preprocessor:
    feature_names: list[str]
    mean: list[float]
    std: list[float]
    threshold: float
    feature_schema_version: str = FEATURE_SCHEMA_VERSION
    dataset_kind: str = "synthetic"
    profile: dict[str, str] | None = None
    training_range: dict[str, str] | None = None

    def transform(self, matrix: list[list[float]]) -> np.ndarray:
        data = np.asarray(matrix, dtype=np.float32)
        mean = np.asarray(self.mean, dtype=np.float32)
        std = np.asarray(self.std, dtype=np.float32)
        return (data - mean) / std


class Autoencoder(nn.Module):
    def __init__(self, input_dim: int) -> None:
        super().__init__()
        hidden = max(4, input_dim // 2)
        latent = max(2, input_dim // 4)
        self.net = nn.Sequential(
            nn.Linear(input_dim, hidden),
            nn.ReLU(),
            nn.Linear(hidden, latent),
            nn.ReLU(),
            nn.Linear(latent, hidden),
            nn.ReLU(),
            nn.Linear(hidden, input_dim),
        )

    def forward(self, value: torch.Tensor) -> torch.Tensor:
        return cast(torch.Tensor, self.net(value))


def set_seed(seed: int) -> None:
    random.seed(seed)
    np.random.seed(seed)
    torch.manual_seed(seed)
    torch.use_deterministic_algorithms(False)


def train_autoencoder(
    matrix: list[list[float]],
    model_dir: Path,
    seed: int = 42,
    epochs: int = 120,
    learning_rate: float = 0.01,
    dataset_kind: str = "synthetic",
    profile: dict[str, str] | None = None,
    training_range: dict[str, str] | None = None,
) -> tuple[Autoencoder, Preprocessor, list[float]]:
    if len(matrix) < 8:
        raise ValueError("at least 8 feature windows are required for training")
    set_seed(seed)
    raw = np.asarray(matrix, dtype=np.float32)
    mean = raw.mean(axis=0)
    std = raw.std(axis=0)
    std[std < 1e-6] = 1.0
    scaled = (raw - mean) / std
    tensor = torch.tensor(scaled, dtype=torch.float32)
    model = Autoencoder(tensor.shape[1])
    optimizer = torch.optim.Adam(model.parameters(), lr=learning_rate)
    loss_fn = nn.MSELoss()
    losses: list[float] = []
    for _ in range(epochs):
        optimizer.zero_grad()
        output = model(tensor)
        loss = loss_fn(output, tensor)
        loss.backward()
        optimizer.step()
        losses.append(float(loss.detach().item()))

    errors = score_matrix(model, scaled)
    threshold = float(np.quantile(errors, 0.98) + np.std(errors))
    preprocessor = Preprocessor(
        feature_names=FEATURE_NAMES.copy(),
        mean=mean.astype(float).tolist(),
        std=std.astype(float).tolist(),
        threshold=threshold,
        dataset_kind=dataset_kind,
        profile=profile,
        training_range=training_range,
    )
    save_model(model, preprocessor, model_dir)
    return model, preprocessor, losses


def score_matrix(model: Autoencoder, scaled_matrix: np.ndarray) -> list[float]:
    scores, _, _ = reconstruct_matrix(model, scaled_matrix)
    return scores


def reconstruct_matrix(
    model: Autoencoder,
    scaled_matrix: np.ndarray,
) -> tuple[list[float], np.ndarray, np.ndarray]:
    with torch.no_grad():
        tensor = torch.tensor(scaled_matrix, dtype=torch.float32)
        reconstructed = model(tensor)
        residuals = (reconstructed - tensor) ** 2
        errors = torch.mean(residuals, dim=1)
    return [float(value) for value in errors.numpy()], reconstructed.numpy(), residuals.numpy()


def save_model(model: Autoencoder, preprocessor: Preprocessor, model_dir: Path) -> None:
    model_dir.mkdir(parents=True, exist_ok=True)
    model_path = model_dir / "autoencoder.pt"
    torch.save(model.state_dict(), model_path)
    model_sha256 = hashlib.sha256(model_path.read_bytes()).hexdigest()
    (model_dir / "preprocessor.json").write_text(json.dumps(asdict(preprocessor), indent=2))
    (model_dir / "model_info.json").write_text(
        json.dumps(
            {
                "model_version": MODEL_VERSION,
                "feature_schema_version": preprocessor.feature_schema_version,
                "dataset_kind": preprocessor.dataset_kind,
                "profile": preprocessor.profile,
                "training_time_range": preprocessor.training_range,
                "created_at": datetime.now(UTC).isoformat(),
                "threshold_method": "quantile_0.98_plus_std",
                "model_sha256": model_sha256,
                "library_versions": {
                    "torch": torch.__version__,
                    "numpy": np.__version__,
                    "sentinelueba": version("sentinelueba"),
                },
                "framework": "pytorch",
                "input_features": preprocessor.feature_names,
            },
            indent=2,
        )
    )


def load_model(model_dir: Path) -> tuple[Autoencoder, Preprocessor]:
    payload = json.loads((model_dir / "preprocessor.json").read_text())
    preprocessor = Preprocessor(**payload)
    if preprocessor.feature_schema_version != FEATURE_SCHEMA_VERSION:
        raise ValueError(
            f"incompatible feature schema: {preprocessor.feature_schema_version}; "
            f"expected {FEATURE_SCHEMA_VERSION}"
        )
    if preprocessor.feature_names != FEATURE_NAMES:
        raise ValueError("incompatible feature list in saved preprocessor")
    info_path = model_dir / "model_info.json"
    model_path = model_dir / "autoencoder.pt"
    if info_path.exists():
        info_payload = json.loads(info_path.read_text())
        if isinstance(info_payload, dict) and "model_sha256" in info_payload:
            expected_sha = str(info_payload["model_sha256"])
            actual_sha = hashlib.sha256(model_path.read_bytes()).hexdigest()
            if actual_sha != expected_sha:
                raise ValueError("model SHA-256 mismatch; refusing to load model")
    model = Autoencoder(len(preprocessor.feature_names))
    state = torch.load(model_path, map_location="cpu", weights_only=True)
    model.load_state_dict(state)
    model.eval()
    return model, preprocessor


def model_info(model_dir: Path) -> dict[str, object]:
    path = model_dir / "model_info.json"
    if not path.exists():
        return {"trained": False}
    payload = json.loads(path.read_text())
    if not isinstance(payload, dict):
        return {"trained": False}
    payload["trained"] = True
    payload["model_dir"] = str(model_dir)
    return cast(dict[str, object], payload)
