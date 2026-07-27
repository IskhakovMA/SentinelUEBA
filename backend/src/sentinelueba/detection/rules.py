from __future__ import annotations

from collections.abc import Callable

from sentinelueba.detection.contracts import (
    DetectionEvidence,
    DetectionInput,
    DetectionRule,
    RuleSignal,
)
from sentinelueba.detection.policies import sha_json

RuleEvaluator = Callable[[DetectionInput, DetectionRule], RuleSignal]


def evaluate_rules(
    detection_input: DetectionInput,
    rules: tuple[DetectionRule, ...],
) -> list[RuleSignal]:
    evaluators: dict[str, RuleEvaluator] = {
        "rare-process-v1": rare_process,
        "new-remote-spike-v1": new_remote_spike,
        "unusual-hour-activity-v1": unusual_hour_activity,
        "resource-pressure-v1": resource_pressure,
        "authentication-failure-burst-v1": authentication_failure_burst,
    }
    signals: list[RuleSignal] = []
    for rule in rules:
        evaluator = evaluators[rule.rule_id]
        signals.append(evaluator(detection_input, rule))
    return signals


def feature_value(detection_input: DetectionInput, name: str) -> float:
    return detection_input.feature_values[detection_input.feature_names.index(name)]


def rare_process(detection_input: DetectionInput, rule: DetectionRule) -> RuleSignal:
    new_process = feature_value(detection_input, "new_process_count")
    process = feature_value(detection_input, "process_count")
    threshold = float(rule.config["new_process_min"])
    matched = bool(
        rule.enabled
        and new_process >= threshold
        and process >= float(rule.config["process_min"])
    )
    strength = min(100, int(float(rule.config["base_strength"]) + max(0.0, new_process - 1) * 5))
    return _signal(
        rule,
        matched=matched,
        strength=strength if matched else 0,
        summary="New process activity in a feature window.",
        feature_name="new_process_count",
        observed=new_process,
        threshold=threshold,
    )


def new_remote_spike(detection_input: DetectionInput, rule: DetectionRule) -> RuleSignal:
    new_remote = feature_value(detection_input, "new_remote_count")
    network = feature_value(detection_input, "network_connection_count")
    threshold = float(rule.config["new_remote_min"])
    matched = bool(
        rule.enabled
        and new_remote >= threshold
        and network >= float(rule.config["network_min"])
    )
    strength = min(
        100,
        int(float(rule.config["base_strength"]) + max(0.0, new_remote - threshold) * 2),
    )
    return _signal(
        rule,
        matched=matched,
        strength=strength if matched else 0,
        summary="New remote destination spike in a feature window.",
        feature_name="new_remote_count",
        observed=new_remote,
        threshold=threshold,
    )


def unusual_hour_activity(detection_input: DetectionInput, rule: DetectionRule) -> RuleSignal:
    hour = int(feature_value(detection_input, "hour_of_day"))
    activity = feature_value(detection_input, "activity_density")
    start = int(rule.config["start_hour"])
    end = int(rule.config["end_hour"])
    threshold = float(rule.config["activity_min"])
    unusual = hour >= start or hour <= end
    matched = bool(rule.enabled and unusual and activity >= threshold)
    strength = min(100, int(float(rule.config["base_strength"]) + max(0.0, activity - threshold)))
    return _signal(
        rule,
        matched=matched,
        strength=strength if matched else 0,
        summary="Activity occurred during an unusual hour for this feature window.",
        feature_name="activity_density",
        observed=activity,
        threshold=threshold,
    )


def resource_pressure(detection_input: DetectionInput, rule: DetectionRule) -> RuleSignal:
    max_cpu = feature_value(detection_input, "max_cpu_percent")
    max_ram = feature_value(detection_input, "max_ram_percent")
    threshold = min(float(rule.config["max_cpu_min"]), float(rule.config["max_ram_min"]))
    observed = max(max_cpu, max_ram)
    matched = bool(
        rule.enabled
        and (
            max_cpu >= float(rule.config["max_cpu_min"])
            or max_ram >= float(rule.config["max_ram_min"])
        )
    )
    strength = min(100, int(float(rule.config["base_strength"]) + max(0.0, observed - threshold)))
    return _signal(
        rule,
        matched=matched,
        strength=strength if matched else 0,
        summary="High CPU or memory pressure in a feature window.",
        feature_name="max_cpu_percent" if max_cpu >= max_ram else "max_ram_percent",
        observed=observed,
        threshold=threshold,
    )


def authentication_failure_burst(
    detection_input: DetectionInput,
    rule: DetectionRule,
) -> RuleSignal:
    failures = feature_value(detection_input, "auth_failure_count")
    threshold = float(rule.config["failure_min"])
    matched = bool(rule.enabled and failures >= threshold)
    strength = min(
        100,
        int(float(rule.config["base_strength"]) + max(0.0, failures - threshold) * 3),
    )
    return _signal(
        rule,
        matched=matched,
        strength=strength if matched else 0,
        summary="Authentication failures burst in a feature window.",
        feature_name="auth_failure_count",
        observed=failures,
        threshold=threshold,
    )


def _signal(
    rule: DetectionRule,
    *,
    matched: bool,
    strength: int,
    summary: str,
    feature_name: str,
    observed: float,
    threshold: float,
) -> RuleSignal:
    return RuleSignal(
        signal_id=rule.rule_id,
        signal_version=rule.rule_version,
        strength=strength,
        matched=matched,
        summary=summary if matched else f"{rule.rule_id} did not match.",
        evidence=(
            DetectionEvidence(
                feature_name=feature_name,
                observed_value=observed,
                threshold_value=threshold,
                direction="above",
                summary=summary,
            ),
        ),
        contributing_feature_names=(feature_name,),
        config_hash=sha_json(rule.model_dump(mode="json")),
    )
