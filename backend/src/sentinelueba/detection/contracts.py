from __future__ import annotations

from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator

from sentinelueba.features.windows import FEATURE_NAMES

SignalSource = Literal["model", "rule"]
DetectionMode = Literal["hybrid", "rules_only", "model_only"]
RiskLevel = Literal["none", "low", "medium", "high", "critical"]
EvaluationStatus = Literal["finding", "no_finding", "skipped", "suppressed"]
FindingStatus = Literal[
    "open",
    "acknowledged",
    "investigating",
    "resolved",
    "false_positive",
    "suppressed",
]


class StrictDetectionModel(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)


class DetectionInput(StrictDetectionModel):
    window_id: str
    dataset_kind: Literal["synthetic", "real"]
    profile_key: str
    window_start: datetime
    window_end: datetime
    feature_schema_version: str
    feature_names: tuple[str, ...] = Field(default=tuple(FEATURE_NAMES))
    feature_values: tuple[float, ...]
    quality: Literal["good", "degraded", "insufficient"]
    feature_input_hash: str

    @field_validator("feature_names")
    @classmethod
    def validate_feature_names(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        if value != tuple(FEATURE_NAMES):
            raise ValueError("feature_names must match the ordered Stage 2 feature contract")
        return value

    @field_validator("feature_values")
    @classmethod
    def validate_feature_values(cls, value: tuple[float, ...]) -> tuple[float, ...]:
        if len(value) != len(FEATURE_NAMES):
            raise ValueError("feature_values length must match FEATURE_NAMES")
        if any(item != item or item in {float("inf"), float("-inf")} for item in value):
            raise ValueError("feature_values contain NaN or Infinity")
        return value


class DetectionRule(StrictDetectionModel):
    rule_id: str
    rule_version: str
    description: str
    enabled: bool = True
    config: dict[str, int | float | str | bool]


class DetectionPolicy(StrictDetectionModel):
    policy_id: str
    policy_version: str
    mode: DetectionMode
    finding_threshold: int = Field(ge=0, le=100)
    risk_thresholds: dict[str, int]
    model_required: bool
    allow_rules_without_model: bool
    rules: tuple[DetectionRule, ...]
    fusion_method: str
    quality_gate: tuple[str, ...]
    policy_hash: str
    created_at: datetime
    source_commit: str


class DetectionEvidence(StrictDetectionModel):
    feature_name: str
    observed_value: float
    threshold_value: float | None = None
    direction: Literal["above", "below", "context"] = "context"
    summary: str


class RuleSignal(StrictDetectionModel):
    signal_id: str
    signal_version: str
    source_type: Literal["rule"] = "rule"
    strength: int = Field(ge=0, le=100)
    matched: bool
    summary: str
    evidence: tuple[DetectionEvidence, ...]
    contributing_feature_names: tuple[str, ...]
    config_hash: str


class ModelSignal(StrictDetectionModel):
    signal_id: str
    signal_version: str
    source_type: Literal["model"] = "model"
    strength: int = Field(ge=0, le=100)
    matched: bool
    summary: str
    evidence: tuple[DetectionEvidence, ...]
    contributing_feature_names: tuple[str, ...]
    config_hash: str
    model_id: str
    model_version: str
    model_hash: str
    anomaly_score: float
    threshold: float


DetectionSignal = RuleSignal | ModelSignal


class DetectionDecision(StrictDetectionModel):
    detection_score: int = Field(ge=0, le=100)
    risk_level: RiskLevel
    matched_signal_ids: tuple[str, ...]
    primary_signal_id: str | None
    corroboration_count: int = Field(ge=0)
    explanation: str
    policy_id: str
    policy_version: str
    policy_hash: str
    model_id: str | None = None
    model_version: str | None = None
    model_hash: str | None = None
    feature_input_hash: str
    finding: bool
    suppressed: bool = False
    skipped_reason: str | None = None


class DetectionRunResult(StrictDetectionModel):
    detection_run_id: str
    status: Literal["success", "partial", "failed", "dry_run"]
    dataset_kind: Literal["synthetic", "real"]
    policy_id: str
    policy_version: str
    policy_hash: str
    mode: DetectionMode
    model_id: str | None
    window_count: int
    evaluated_count: int
    skipped_count: int
    finding_count: int
    no_op_count: int
    dry_run: bool
    safe_error: str | None = None


class Finding(StrictDetectionModel):
    finding_id: str
    fingerprint: str
    dataset_kind: Literal["synthetic", "real"]
    profile_key: str
    status: FindingStatus
    risk_level: RiskLevel
    detection_score: int
    primary_signal_id: str
    title: str
    summary: str
    first_seen_at: datetime
    last_seen_at: datetime
    occurrence_count: int


class FindingOccurrence(StrictDetectionModel):
    occurrence_id: str
    finding_id: str
    evaluation_id: str
    window_id: str
    window_start: datetime
    window_end: datetime
    detection_score: int
    risk_level: RiskLevel
    signals: tuple[str, ...]
    evidence: dict[str, Any]
