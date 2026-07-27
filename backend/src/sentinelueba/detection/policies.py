from __future__ import annotations

import hashlib
import json
import subprocess
from datetime import UTC, datetime
from typing import Any

from sentinelueba.detection.contracts import DetectionPolicy, DetectionRule

DEFAULT_POLICY_ID = "hybrid-policy-v1"
DEFAULT_POLICY_VERSION = "2026-07-27"
DEFAULT_FUSION_METHOD = "hybrid-fusion-v1"
MODEL_STRENGTH_VERSION = "model-strength-v1"


def canonical_json(payload: dict[str, Any]) -> str:
    return json.dumps(payload, sort_keys=True, separators=(",", ":"))


def sha_json(payload: dict[str, Any]) -> str:
    return hashlib.sha256(canonical_json(payload).encode("utf-8")).hexdigest()


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
            config={"new_process_min": 1, "process_min": 1, "base_strength": 60},
        ),
        DetectionRule(
            rule_id="new-remote-spike-v1",
            rule_version="1",
            description="New remote destination activity spikes in a feature window.",
            config={"new_remote_min": 3, "network_min": 10, "base_strength": 66},
        ),
        DetectionRule(
            rule_id="unusual-hour-activity-v1",
            rule_version="1",
            description="Meaningful process or network activity occurs during unusual hours.",
            config={"start_hour": 22, "end_hour": 5, "activity_min": 12, "base_strength": 58},
        ),
        DetectionRule(
            rule_id="resource-pressure-v1",
            rule_version="1",
            description="CPU or memory pressure is high in a feature window.",
            config={"max_cpu_min": 90, "max_ram_min": 90, "base_strength": 64},
        ),
        DetectionRule(
            rule_id="authentication-failure-burst-v1",
            rule_version="1",
            description="Authentication failures burst within a feature window.",
            config={"failure_min": 5, "base_strength": 70},
        ),
    )


def default_policy(*, source_commit: str | None = None) -> DetectionPolicy:
    created_at = datetime(2026, 1, 1, tzinfo=UTC)
    hash_payload = {
        "policy_id": DEFAULT_POLICY_ID,
        "policy_version": DEFAULT_POLICY_VERSION,
        "mode": "hybrid",
        "finding_threshold": 55,
        "risk_thresholds": {"low": 35, "medium": 55, "high": 75, "critical": 90},
        "model_required": False,
        "allow_rules_without_model": True,
        "fusion_method": DEFAULT_FUSION_METHOD,
        "quality_gate": ["good"],
        "rules": [
            rule.model_dump(mode="json", exclude_none=True) for rule in default_rules()
        ],
    }
    policy_hash = sha_json(hash_payload)
    return DetectionPolicy(
        policy_id=DEFAULT_POLICY_ID,
        policy_version=DEFAULT_POLICY_VERSION,
        mode="hybrid",
        finding_threshold=55,
        risk_thresholds={"low": 35, "medium": 55, "high": 75, "critical": 90},
        model_required=False,
        allow_rules_without_model=True,
        rules=default_rules(),
        fusion_method=DEFAULT_FUSION_METHOD,
        quality_gate=("good",),
        policy_hash=policy_hash,
        created_at=created_at,
        source_commit=source_commit or safe_source_commit(),
    )


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


def load_policy(payload: dict[str, Any]) -> DetectionPolicy:
    raw = json.loads(str(payload["policy_json"]))
    raw["policy_hash"] = payload["policy_hash"]
    raw["created_at"] = datetime.fromisoformat(str(raw["created_at"]))
    raw["rules"] = tuple(DetectionRule(**item) for item in raw["rules"])
    raw["quality_gate"] = tuple(raw["quality_gate"])
    return DetectionPolicy(**raw)
