from __future__ import annotations

import math
from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

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


class RiskThresholdConfig(StrictDetectionModel):
    low: int = Field(ge=0, le=100)
    medium: int = Field(ge=0, le=100)
    high: int = Field(ge=0, le=100)
    critical: int = Field(ge=0, le=100)

    @model_validator(mode="after")
    def validate_order(self) -> RiskThresholdConfig:
        if not self.low < self.medium < self.high < self.critical:
            raise ValueError("risk thresholds must satisfy low < medium < high < critical")
        return self

    def as_dict(self) -> dict[str, int]:
        return {
            "low": self.low,
            "medium": self.medium,
            "high": self.high,
            "critical": self.critical,
        }


class FiniteConfig(StrictDetectionModel):
    @field_validator("*")
    @classmethod
    def finite_numbers(cls, value: object) -> object:
        if isinstance(value, float) and not math.isfinite(value):
            raise ValueError("config values must be finite")
        return value


class RareProcessRuleConfig(FiniteConfig):
    new_process_min: int = Field(ge=1, le=10_000)
    process_min: int = Field(ge=1, le=100_000)
    activity_min: float = Field(ge=0, le=100_000)
    base_strength: int = Field(ge=1, le=100)


class NewRemoteSpikeRuleConfig(FiniteConfig):
    new_remote_min: int = Field(ge=1, le=100_000)
    network_min: int = Field(ge=1, le=1_000_000)
    activity_min: float = Field(ge=0, le=100_000)
    base_strength: int = Field(ge=1, le=100)


class UnusualHourRuleConfig(FiniteConfig):
    start_hour: int = Field(ge=0, le=23)
    end_hour: int = Field(ge=0, le=23)
    activity_min: float = Field(ge=0, le=100_000)
    process_network_min: float = Field(ge=0, le=1_000_000)
    base_strength: int = Field(ge=1, le=100)


class ResourcePressureRuleConfig(FiniteConfig):
    avg_cpu_min: float = Field(ge=0, le=100)
    max_cpu_min: float = Field(ge=0, le=100)
    avg_ram_min: float = Field(ge=0, le=100)
    max_ram_min: float = Field(ge=0, le=100)
    base_strength: int = Field(ge=1, le=100)


class AuthenticationFailureBurstRuleConfig(FiniteConfig):
    failure_min: int = Field(ge=1, le=100_000)
    success_max: int = Field(ge=0, le=100_000)
    activity_min: float = Field(ge=0, le=100_000)
    base_strength: int = Field(ge=1, le=100)


RuleConfig = (
    RareProcessRuleConfig
    | NewRemoteSpikeRuleConfig
    | UnusualHourRuleConfig
    | ResourcePressureRuleConfig
    | AuthenticationFailureBurstRuleConfig
)


class DetectionRule(StrictDetectionModel):
    rule_id: str
    rule_version: str
    description: str
    enabled: bool = True
    config: RuleConfig


class DetectionPolicy(StrictDetectionModel):
    policy_id: str
    policy_version: str
    mode: DetectionMode
    finding_threshold: int = Field(ge=0, le=100)
    risk_thresholds: RiskThresholdConfig
    model_required: bool
    allow_rules_without_model: bool
    rules: tuple[DetectionRule, ...]
    fusion_method: str
    quality_gate: tuple[str, ...]
    policy_hash: str
    created_at: datetime
    source_commit: str

    @model_validator(mode="after")
    def validate_policy(self) -> DetectionPolicy:
        if self.fusion_method != "hybrid-fusion-v1":
            raise ValueError("unknown detection fusion method")
        if not self.quality_gate:
            raise ValueError("quality_gate must not be empty")
        if not set(self.quality_gate).issubset({"good", "degraded", "insufficient"}):
            raise ValueError("quality_gate contains unknown quality status")
        ids = [rule.rule_id for rule in self.rules]
        if len(ids) != len(set(ids)):
            raise ValueError("rule ids must not repeat")
        known = {
            "rare-process-v1": RareProcessRuleConfig,
            "new-remote-spike-v1": NewRemoteSpikeRuleConfig,
            "unusual-hour-activity-v1": UnusualHourRuleConfig,
            "resource-pressure-v1": ResourcePressureRuleConfig,
            "authentication-failure-burst-v1": AuthenticationFailureBurstRuleConfig,
        }
        for rule in self.rules:
            expected = known.get(rule.rule_id)
            if expected is None:
                raise ValueError(f"unknown detection rule id: {rule.rule_id}")
            if not isinstance(rule.config, expected):
                raise ValueError(f"{rule.rule_id} uses wrong config type")
        return self


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
    suppression: dict[str, Any] | None = None


class DetectionRunResult(StrictDetectionModel):
    detection_run_id: str | None = None
    child_run_ids: tuple[str, ...] = ()
    status: Literal["success", "partial", "failed", "blocked", "dry_run"]
    dataset_kind: Literal["synthetic", "real"]
    policy_id: str
    policy_version: str
    policy_hash: str
    mode: DetectionMode
    model_id: str | None
    window_count: int
    examined_count: int = 0
    evaluated_count: int
    skipped_count: int
    finding_count: int
    new_findings: int = 0
    updated_findings: int = 0
    finding_occurrences: int = 0
    no_op_count: int
    dry_run: bool
    blocked_reason: str | None = None
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


class SuppressionRequest(StrictDetectionModel):
    scope: Literal["finding_fingerprint", "signal_for_profile", "signal_for_dataset_kind"]
    reason: str = Field(min_length=1, max_length=500)
    ttl_minutes: int = Field(ge=1, le=525_600)
    dataset_kind: Literal["synthetic", "real"] | None = None
    profile_key: str | None = None
    finding_fingerprint: str | None = None
    signal_id: str | None = None

    @model_validator(mode="after")
    def validate_scope_fields(self) -> SuppressionRequest:
        if self.scope == "finding_fingerprint":
            if not self.finding_fingerprint:
                raise ValueError("finding_fingerprint scope requires fingerprint")
            if self.profile_key or self.signal_id or self.dataset_kind:
                raise ValueError("finding_fingerprint scope forbids profile, signal, and dataset")
        elif self.scope == "signal_for_profile":
            if not self.profile_key or not self.signal_id:
                raise ValueError("signal_for_profile requires profile_key and signal_id")
            if self.dataset_kind or self.finding_fingerprint:
                raise ValueError("signal_for_profile forbids dataset and fingerprint")
        elif self.scope == "signal_for_dataset_kind":
            if not self.dataset_kind or not self.signal_id:
                raise ValueError("signal_for_dataset_kind requires dataset_kind and signal_id")
            if self.profile_key or self.finding_fingerprint:
                raise ValueError("signal_for_dataset_kind forbids profile and fingerprint")
        return self
