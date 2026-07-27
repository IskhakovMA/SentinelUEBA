from __future__ import annotations

import hashlib
import json
import subprocess
from datetime import UTC, datetime
from typing import Any

from sentinelueba.detection.contracts import (
    AuthenticationFailureBurstRuleConfig,
    DetectionPolicy,
    DetectionRule,
    NewRemoteSpikeRuleConfig,
    RareProcessRuleConfig,
    ResourcePressureRuleConfig,
    RiskThresholdConfig,
    RuleConfig,
    UnusualHourRuleConfig,
)

DEFAULT_POLICY_ID = "hybrid-policy-v1"
RULES_ONLY_POLICY_ID = "rules-only-policy-v1"
DEFAULT_POLICY_VERSION = "2026-07-27"
DEFAULT_FUSION_METHOD = "hybrid-fusion-v1"
MODEL_STRENGTH_VERSION = "model-strength-v1"
KNOWN_RULE_IDS = {
    "rare-process-v1",
    "new-remote-spike-v1",
    "unusual-hour-activity-v1",
    "resource-pressure-v1",
    "authentication-failure-burst-v1",
}
KNOWN_SIGNAL_IDS = KNOWN_RULE_IDS | {
    "model-autoencoder-autoencoder-v2",
    "model-isolation-forest-isolation-forest-v1",
}


def canonical_json(payload: dict[str, Any]) -> str:
    return json.dumps(payload, sort_keys=True, separators=(",", ":"))


def sha_json(payload: dict[str, Any]) -> str:
    return hashlib.sha256(canonical_json(payload).encode("utf-8")).hexdigest()


def canonical_policy_payload(policy: DetectionPolicy) -> dict[str, Any]:
    return {
        "policy_id": policy.policy_id,
        "policy_version": policy.policy_version,
        "mode": policy.mode,
        "finding_threshold": policy.finding_threshold,
        "risk_thresholds": policy.risk_thresholds.model_dump(mode="json"),
        "model_required": policy.model_required,
        "allow_rules_without_model": policy.allow_rules_without_model,
        "fusion_method": policy.fusion_method,
        "quality_gate": list(policy.quality_gate),
        "rules": [
            rule.model_dump(mode="json", exclude_none=True) for rule in policy.rules
        ],
    }


def policy_hash(policy: DetectionPolicy) -> str:
    return sha_json(canonical_policy_payload(policy))


def safe_source_commit() -> str:
    try:
        return subprocess.check_output(["git", "rev-parse", "HEAD"], text=True).strip()
    except Exception:
        return "unknown"


def sanitize_reason(value: str, *, limit: int = 500) -> str:
    cleaned = " ".join(value.replace("\x00", " ").split())
    return cleaned[:limit] or "manual update"


def default_rules() -> tuple[DetectionRule, ...]:
    return (
        DetectionRule(
            rule_id="rare-process-v1",
            rule_version="1",
            description="New process activity appears in a finalized feature window.",
            config=RareProcessRuleConfig(
                new_process_min=1,
                process_min=1,
                activity_min=0,
                base_strength=60,
            ),
        ),
        DetectionRule(
            rule_id="new-remote-spike-v1",
            rule_version="1",
            description="New remote destination activity spikes in a feature window.",
            config=NewRemoteSpikeRuleConfig(
                new_remote_min=3,
                network_min=10,
                activity_min=0,
                base_strength=66,
            ),
        ),
        DetectionRule(
            rule_id="unusual-hour-activity-v1",
            rule_version="1",
            description="Meaningful process or network activity occurs during unusual hours.",
            config=UnusualHourRuleConfig(
                start_hour=22,
                end_hour=5,
                activity_min=12,
                process_network_min=1,
                base_strength=58,
            ),
        ),
        DetectionRule(
            rule_id="resource-pressure-v1",
            rule_version="1",
            description="CPU or memory pressure is high in a feature window.",
            config=ResourcePressureRuleConfig(
                avg_cpu_min=70,
                max_cpu_min=90,
                avg_ram_min=85,
                max_ram_min=90,
                base_strength=64,
            ),
        ),
        DetectionRule(
            rule_id="authentication-failure-burst-v1",
            rule_version="1",
            description="Authentication failures burst within a feature window.",
            config=AuthenticationFailureBurstRuleConfig(
                failure_min=5,
                success_max=100_000,
                activity_min=0,
                base_strength=70,
            ),
        ),
    )


def default_policy(*, source_commit: str | None = None) -> DetectionPolicy:
    return _built_in_policy(
        policy_id=DEFAULT_POLICY_ID,
        mode="hybrid",
        model_required=False,
        allow_rules_without_model=True,
        source_commit=source_commit,
    )


def rules_only_policy(*, source_commit: str | None = None) -> DetectionPolicy:
    return _built_in_policy(
        policy_id=RULES_ONLY_POLICY_ID,
        mode="rules_only",
        model_required=False,
        allow_rules_without_model=True,
        source_commit=source_commit,
    )


def built_in_policies(*, source_commit: str | None = None) -> tuple[DetectionPolicy, ...]:
    return (
        default_policy(source_commit=source_commit),
        rules_only_policy(source_commit=source_commit),
    )


def _built_in_policy(
    *,
    policy_id: str,
    mode: str,
    model_required: bool,
    allow_rules_without_model: bool,
    source_commit: str | None = None,
) -> DetectionPolicy:
    created_at = datetime(2026, 1, 1, tzinfo=UTC)
    policy = DetectionPolicy(
        policy_id=policy_id,
        policy_version=DEFAULT_POLICY_VERSION,
        mode=mode,  # type: ignore[arg-type]
        finding_threshold=55,
        risk_thresholds=RiskThresholdConfig(low=35, medium=55, high=75, critical=90),
        model_required=model_required,
        allow_rules_without_model=allow_rules_without_model,
        rules=default_rules(),
        fusion_method=DEFAULT_FUSION_METHOD,
        quality_gate=("good",),
        policy_hash="pending",
        created_at=created_at,
        source_commit=source_commit or safe_source_commit(),
    )
    return policy.model_copy(update={"policy_hash": policy_hash(policy)})


def policy_storage_payload(policy: DetectionPolicy) -> dict[str, object]:
    return {
        "policy_id": policy.policy_id,
        "policy_version": policy.policy_version,
        "policy_hash": policy.policy_hash,
        "mode": policy.mode,
        "policy_json": json.dumps(policy.model_dump(mode="json"), sort_keys=True),
        "active": 1,
        "created_at": policy.created_at.isoformat(),
        "source_commit": policy.source_commit,
    }


def parse_rule(raw: dict[str, Any]) -> DetectionRule:
    config_by_id: dict[str, type[RuleConfig]] = {
        "rare-process-v1": RareProcessRuleConfig,
        "new-remote-spike-v1": NewRemoteSpikeRuleConfig,
        "unusual-hour-activity-v1": UnusualHourRuleConfig,
        "resource-pressure-v1": ResourcePressureRuleConfig,
        "authentication-failure-burst-v1": AuthenticationFailureBurstRuleConfig,
    }
    rule_id = str(raw.get("rule_id"))
    config_cls = config_by_id.get(rule_id)
    if config_cls is None:
        raise ValueError(f"unknown detection rule id: {rule_id}")
    payload = dict(raw)
    payload["config"] = config_cls(**payload["config"])
    return DetectionRule(**payload)


def load_policy(payload: dict[str, Any]) -> DetectionPolicy:
    raw = json.loads(str(payload["policy_json"]))
    raw["created_at"] = datetime.fromisoformat(str(raw["created_at"]))
    raw["rules"] = tuple(parse_rule(item) for item in raw["rules"])
    raw["quality_gate"] = tuple(raw["quality_gate"])
    raw["risk_thresholds"] = RiskThresholdConfig(**raw["risk_thresholds"])
    raw["policy_hash"] = str(raw.get("policy_hash") or payload["policy_hash"])
    policy = DetectionPolicy(**raw)
    if policy.policy_hash != str(payload["policy_hash"]):
        raise ValueError("detection policy hash column mismatch")
    if policy.policy_id != str(payload["policy_id"]):
        raise ValueError("detection policy id column mismatch")
    if policy.policy_version != str(payload["policy_version"]):
        raise ValueError("detection policy version column mismatch")
    if policy.mode != str(payload["mode"]):
        raise ValueError("detection policy mode column mismatch")
    recalculated = policy_hash(policy)
    if recalculated != policy.policy_hash:
        raise ValueError("detection policy hash mismatch")
    return policy
