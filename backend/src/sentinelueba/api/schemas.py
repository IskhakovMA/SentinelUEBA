from __future__ import annotations

from typing import Any

from pydantic import BaseModel, Field


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


class MLTrainRequest(BaseModel):
    dataset_kind: str = Field(default="synthetic", pattern="^(synthetic|real)$")
    dataset_id: str | None = None
    families: list[str] | None = None
    seed: int = Field(default=42, ge=0, le=1_000_000)
    target_fpr: float = Field(default=0.05, gt=0, lt=1)


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


class MLDriftRequest(BaseModel):
    model_id: str
    dataset_id: str


class ApiResponse(BaseModel):
    data: dict[str, Any]


class AnomalyListResponse(BaseModel):
    anomalies: list[dict[str, Any]]


class ErrorResponse(BaseModel):
    detail: str
