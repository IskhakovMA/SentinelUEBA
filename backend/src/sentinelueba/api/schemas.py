from __future__ import annotations

from typing import Any

from pydantic import BaseModel, Field, field_validator


class SeedRequest(BaseModel):
    seed: int = Field(default=42, ge=0, le=1_000_000)


class CollectionStartRequest(BaseModel):
    duration_seconds: int | None = Field(default=None, ge=1, le=86_400)
    interval_seconds: float = Field(default=5.0, ge=0.5, le=3600)


class TrainingEligibilityRequest(BaseModel):
    dataset_kind: str = Field(default="real", pattern="^(synthetic|real)$")


class DatasetKindRequest(BaseModel):
    dataset_kind: str = Field(default="synthetic", pattern="^(synthetic|real)$")


class RetentionApplyRequest(BaseModel):
    confirm: bool = False


class AutoencoderTrainConfig(BaseModel):
    epochs: int = Field(default=80, ge=1, le=300)
    batch_size: int = Field(default=16, ge=1, le=4096)
    learning_rate: float = Field(default=0.005, gt=0, le=1)
    weight_decay: float = Field(default=0.0001, ge=0, le=1)
    hidden_dim: int = Field(default=10, ge=2, le=256)
    latent_dim: int = Field(default=4, ge=1, le=128)
    plateau_patience: int = Field(default=12, ge=1, le=100)


class IsolationForestTrainConfig(BaseModel):
    n_estimators: int = Field(default=80, ge=10, le=500)
    max_samples: str | int | float = "auto"
    max_features: float = Field(default=1.0, gt=0, le=1)
    bootstrap: bool = False
    n_jobs: int = Field(default=1, ge=1, le=2)

    @field_validator("max_samples")
    @classmethod
    def validate_max_samples(cls, value: str | int | float) -> str | int | float:
        if value == "auto":
            return value
        if isinstance(value, bool):
            raise ValueError("max_samples must be auto, a positive int, or a float in (0, 1]")
        if isinstance(value, int):
            if value < 1:
                raise ValueError("max_samples int must be positive")
            return value
        if isinstance(value, float):
            if not 0 < value <= 1:
                raise ValueError("max_samples float must be in (0, 1]")
            return value
        raise ValueError("max_samples must be auto, a positive int, or a float in (0, 1]")


class MLTrainRequest(BaseModel):
    dataset_kind: str = Field(default="synthetic", pattern="^(synthetic|real)$")
    dataset_id: str | None = None
    families: list[str] | None = None
    seed: int = Field(default=42, ge=0, le=1_000_000)
    target_fpr: float = Field(default=0.05, gt=0, lt=1)
    autoencoder: AutoencoderTrainConfig | None = None
    isolation_forest: IsolationForestTrainConfig | None = None


class MLConfirmRequest(BaseModel):
    confirm: bool = False
    reason: str = "manual operation"


class MLCompareRequest(BaseModel):
    model_ids: list[str]


class MLEvaluateRequest(BaseModel):
    model_id: str


class MLScoreRequest(BaseModel):
    dataset_id: str
    model_id: str | None = None
    dataset_kind: str | None = Field(default=None, pattern="^(synthetic|real)$")
    batch_size: int = Field(default=256, ge=1, le=4096)


class MLDriftRequest(BaseModel):
    model_id: str
    dataset_id: str


class DetectionRunRequest(BaseModel):
    dataset_kind: str = Field(default="synthetic", pattern="^(synthetic|real)$")
    profile: str | None = None
    policy_id: str | None = None
    policy_version: str | None = None
    model_id: str | None = None
    start: str | None = None
    end: str | None = None
    batch_size: int = Field(default=256, ge=1, le=4096)
    max_windows: int | None = Field(default=None, ge=1)
    rules_only: bool = False
    dry_run: bool = False


class DetectionBackfillRequest(BaseModel):
    dataset_kind: str = Field(default="synthetic", pattern="^(synthetic|real)$")
    policy_id: str | None = None
    policy_version: str | None = None
    model_id: str | None = None
    start: str | None = None
    end: str | None = None
    dataset_id: str | None = None
    confirm: bool = False
    advance_watermark: bool = False
    confirm_advance_watermark: bool = False


class DetectionPolicyActivateRequest(BaseModel):
    policy_version: str | None = None
    confirm: bool = False
    reason: str = "manual policy activation"


class FindingTransitionRequest(BaseModel):
    reason: str = "manual update"
    confirm: bool = False


class SuppressionCreateRequest(BaseModel):
    scope: str = Field(pattern="^(finding_fingerprint|signal_for_profile|signal_for_dataset_kind)$")
    reason: str = Field(min_length=1, max_length=500)
    ttl_minutes: int = Field(ge=1, le=525_600)
    dataset_kind: str | None = Field(default=None, pattern="^(synthetic|real)$")
    profile_key: str | None = None
    finding_fingerprint: str | None = None
    signal_id: str | None = None


class DetectionWorkerStartRequest(BaseModel):
    dataset_kind: str = Field(default="synthetic", pattern="^(synthetic|real)$")
    interval_seconds: int = Field(default=60, ge=5, le=3600)
    max_windows: int | None = Field(default=256, ge=1, le=10_000)


class DetectionWorkerRunRequest(BaseModel):
    dataset_kind: str = Field(default="synthetic", pattern="^(synthetic|real)$")
    max_windows: int | None = Field(default=256, ge=1, le=10_000)
    interval_seconds: int = Field(default=60, ge=5, le=3600)
    single_cycle: bool = False


class ConfirmRequest(BaseModel):
    confirm: bool = False


class DetectionWorkerStopRequest(BaseModel):
    dataset_kind: str = Field(default="synthetic", pattern="^(synthetic|real)$")
    confirm: bool = False


class ApiResponse(BaseModel):
    data: dict[str, Any]


class AnomalyListResponse(BaseModel):
    anomalies: list[dict[str, Any]]


class ErrorResponse(BaseModel):
    detail: str
