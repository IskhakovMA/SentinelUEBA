from __future__ import annotations

from typing import Any

from pydantic import BaseModel, Field


class SeedRequest(BaseModel):
    seed: int = Field(default=42, ge=0, le=1_000_000)


class ApiResponse(BaseModel):
    data: dict[str, Any]


class AnomalyListResponse(BaseModel):
    anomalies: list[dict[str, Any]]


class ErrorResponse(BaseModel):
    detail: str

