from __future__ import annotations

from sentinelueba.detection.contracts import (
    DetectionDecision,
    DetectionInput,
    DetectionPolicy,
    DetectionSignal,
    RiskLevel,
    RiskThresholdConfig,
)


def fuse_signals(
    detection_input: DetectionInput,
    policy: DetectionPolicy,
    signals: list[DetectionSignal],
    *,
    model_id: str | None,
    model_version: str | None,
    model_hash: str | None,
    suppressed: bool = False,
) -> DetectionDecision:
    matched = [signal for signal in signals if signal.matched]
    if not matched:
        return DetectionDecision(
            detection_score=0,
            risk_level="none",
            matched_signal_ids=(),
            primary_signal_id=None,
            corroboration_count=0,
            explanation="No Stage 4 model or rule signal reached its match condition.",
            policy_id=policy.policy_id,
            policy_version=policy.policy_version,
            policy_hash=policy.policy_hash,
            model_id=model_id,
            model_version=model_version,
            model_hash=model_hash,
            feature_input_hash=detection_input.feature_input_hash,
            finding=False,
            suppressed=suppressed,
        )
    matched = sorted(matched, key=lambda item: (-item.strength, item.signal_id))
    primary = matched[0]
    secondary_bonus = sum(int(round(item.strength * 0.25)) for item in matched[1:])
    corroboration_bonus = min(12, max(0, len(matched) - 1) * 4)
    score = min(100, primary.strength + secondary_bonus + corroboration_bonus)
    risk = risk_for_score(score, policy.risk_thresholds)
    finding = score >= policy.finding_threshold and not suppressed
    explanation = (
        f"{policy.fusion_method} selected {primary.signal_id} as the primary signal; "
        f"{max(0, len(matched) - 1)} corroborating signal(s) contributed to score {score}. "
        "A finding is an analyst triage item, not proof of compromise."
    )
    return DetectionDecision(
        detection_score=score,
        risk_level=risk,
        matched_signal_ids=tuple(item.signal_id for item in matched),
        primary_signal_id=primary.signal_id,
        corroboration_count=max(0, len(matched) - 1),
        explanation=explanation,
        policy_id=policy.policy_id,
        policy_version=policy.policy_version,
        policy_hash=policy.policy_hash,
        model_id=model_id,
        model_version=model_version,
        model_hash=model_hash,
        feature_input_hash=detection_input.feature_input_hash,
        finding=finding,
        suppressed=suppressed,
    )


def risk_for_score(score: int, thresholds: RiskThresholdConfig) -> RiskLevel:
    if score >= thresholds.critical:
        return "critical"
    if score >= thresholds.high:
        return "high"
    if score >= thresholds.medium:
        return "medium"
    if score >= thresholds.low:
        return "low"
    return "none"
