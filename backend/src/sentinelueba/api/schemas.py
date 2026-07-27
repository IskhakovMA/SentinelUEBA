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


class ApiResponse(BaseModel):
    data: dict[str, Any]


class AnomalyListResponse(BaseModel):
    anomalies: list[dict[str, Any]]


class ErrorResponse(BaseModel):
    detail: str
