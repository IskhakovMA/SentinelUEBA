from __future__ import annotations

from collections.abc import Callable
from typing import cast

from sentinelueba.detection.contracts import (
    AuthenticationFailureBurstRuleConfig,
    DetectionEvidence,
    DetectionInput,
    DetectionRule,
    NewRemoteSpikeRuleConfig,
    RareProcessRuleConfig,
    ResourcePressureRuleConfig,
    RuleSignal,
    UnusualHourRuleConfig,
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
    config = _config(rule, RareProcessRuleConfig)
    new_process = feature_value(detection_input, "new_process_count")
    process = feature_value(detection_input, "process_count")
    activity = feature_value(detection_input, "activity_density")
    threshold = float(config.new_process_min)
    matched = bool(
        rule.enabled
        and new_process >= threshold
        and process >= config.process_min
        and activity >= config.activity_min
    )
    strength = min(100, int(config.base_strength + max(0.0, new_process - 1) * 5))
    return _signal(
        rule,
        matched=matched,
        strength=strength if matched else 0,
        summary="New process activity in a feature window.",
        evidence=(
            _evidence("new_process_count", new_process, threshold, "New process count."),
            _evidence(
                "process_count",
                process,
                float(config.process_min),
                "Process activity gate.",
            ),
            _evidence("activity_density", activity, config.activity_min, "Activity density gate."),
        ),
    )


def new_remote_spike(detection_input: DetectionInput, rule: DetectionRule) -> RuleSignal:
    config = _config(rule, NewRemoteSpikeRuleConfig)
    new_remote = feature_value(detection_input, "new_remote_count")
    network = feature_value(detection_input, "network_connection_count")
    activity = feature_value(detection_input, "activity_density")
    threshold = float(config.new_remote_min)
    matched = bool(
        rule.enabled
        and new_remote >= threshold
        and network >= config.network_min
        and activity >= config.activity_min
    )
    strength = min(
        100,
        int(config.base_strength + max(0.0, new_remote - threshold) * 2),
    )
    return _signal(
        rule,
        matched=matched,
        strength=strength if matched else 0,
        summary="New remote destination spike in a feature window.",
        evidence=(
            _evidence("new_remote_count", new_remote, threshold, "New remote count."),
            _evidence(
                "network_connection_count",
                network,
                float(config.network_min),
                "Network activity gate.",
            ),
            _evidence("activity_density", activity, config.activity_min, "Activity density gate."),
        ),
    )


def unusual_hour_activity(detection_input: DetectionInput, rule: DetectionRule) -> RuleSignal:
    config = _config(rule, UnusualHourRuleConfig)
    hour = int(feature_value(detection_input, "hour_of_day"))
    activity = feature_value(detection_input, "activity_density")
    process_network = feature_value(detection_input, "process_count") + feature_value(
        detection_input,
        "network_connection_count",
    )
    start = config.start_hour
    end = config.end_hour
    threshold = config.activity_min
    unusual = hour >= start or hour <= end
    matched = bool(
        rule.enabled
        and unusual
        and activity >= threshold
        and process_network >= config.process_network_min
    )
    strength = min(100, int(config.base_strength + max(0.0, activity - threshold)))
    return _signal(
        rule,
        matched=matched,
        strength=strength if matched else 0,
        summary="Activity occurred during an unusual hour for this feature window.",
        evidence=(
            _evidence("hour_of_day", float(hour), float(start), "Unusual hour gate."),
            _evidence("activity_density", activity, threshold, "Activity density gate."),
            _evidence(
                "process_count",
                feature_value(detection_input, "process_count"),
                None,
                "Process side of process/network gate.",
            ),
            _evidence(
                "network_connection_count",
                feature_value(detection_input, "network_connection_count"),
                None,
                "Network side of process/network gate.",
            ),
        ),
    )


def resource_pressure(detection_input: DetectionInput, rule: DetectionRule) -> RuleSignal:
    config = _config(rule, ResourcePressureRuleConfig)
    avg_cpu = feature_value(detection_input, "avg_cpu_percent")
    max_cpu = feature_value(detection_input, "max_cpu_percent")
    avg_ram = feature_value(detection_input, "avg_ram_percent")
    max_ram = feature_value(detection_input, "max_ram_percent")
    threshold = min(config.avg_cpu_min, config.max_cpu_min, config.avg_ram_min, config.max_ram_min)
    observed = max(max_cpu, max_ram)
    matched = bool(
        rule.enabled
        and (
            avg_cpu >= config.avg_cpu_min
            or max_cpu >= config.max_cpu_min
            or avg_ram >= config.avg_ram_min
            or max_ram >= config.max_ram_min
        )
    )
    strength = min(100, int(config.base_strength + max(0.0, observed - threshold)))
    return _signal(
        rule,
        matched=matched,
        strength=strength if matched else 0,
        summary="High CPU or memory pressure in a feature window.",
        evidence=(
            _evidence("avg_cpu_percent", avg_cpu, config.avg_cpu_min, "Average CPU gate."),
            _evidence("max_cpu_percent", max_cpu, config.max_cpu_min, "Maximum CPU gate."),
            _evidence("avg_ram_percent", avg_ram, config.avg_ram_min, "Average RAM gate."),
            _evidence("max_ram_percent", max_ram, config.max_ram_min, "Maximum RAM gate."),
        ),
    )


def authentication_failure_burst(
    detection_input: DetectionInput,
    rule: DetectionRule,
) -> RuleSignal:
    config = _config(rule, AuthenticationFailureBurstRuleConfig)
    failures = feature_value(detection_input, "auth_failure_count")
    successes = feature_value(detection_input, "auth_success_count")
    activity = feature_value(detection_input, "activity_density")
    threshold = float(config.failure_min)
    matched = bool(
        rule.enabled
        and failures >= threshold
        and successes <= config.success_max
        and activity >= config.activity_min
    )
    strength = min(
        100,
        int(config.base_strength + max(0.0, failures - threshold) * 3),
    )
    return _signal(
        rule,
        matched=matched,
        strength=strength if matched else 0,
        summary="Authentication failures burst in a feature window.",
        evidence=(
            _evidence("auth_failure_count", failures, threshold, "Authentication failure count."),
            _evidence(
                "auth_success_count",
                successes,
                float(config.success_max),
                "Authentication success gate.",
            ),
            _evidence("activity_density", activity, config.activity_min, "Activity density gate."),
        ),
    )


def _signal(
    rule: DetectionRule,
    *,
    matched: bool,
    strength: int,
    summary: str,
    evidence: tuple[DetectionEvidence, ...],
) -> RuleSignal:
    return RuleSignal(
        signal_id=rule.rule_id,
        signal_version=rule.rule_version,
        strength=strength,
        matched=matched,
        summary=summary if matched else f"{rule.rule_id} did not match.",
        evidence=evidence,
        contributing_feature_names=tuple(item.feature_name for item in evidence),
        config_hash=sha_json(rule.model_dump(mode="json")),
    )


def _evidence(
    feature_name: str,
    observed: float,
    threshold: float | None,
    summary: str,
) -> DetectionEvidence:
    return DetectionEvidence(
        feature_name=feature_name,
        observed_value=observed,
        threshold_value=threshold,
        direction="above",
        summary=summary,
    )


def _config[ConfigT](rule: DetectionRule, config_type: type[ConfigT]) -> ConfigT:
    if not isinstance(rule.config, config_type):
        raise ValueError(f"{rule.rule_id} uses wrong config type")
    return cast(ConfigT, rule.config)
