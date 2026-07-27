from __future__ import annotations

from datetime import datetime

import numpy as np

from sentinelueba.domain.events import AnomalyRecord, AnomalyRisk, WindowFeatures
from sentinelueba.ml.autoencoder import MODEL_VERSION, Autoencoder, Preprocessor, score_matrix


def classify_risk(score: float, threshold: float) -> AnomalyRisk:
    if score < threshold:
        return AnomalyRisk.NORMAL
    ratio = score / max(threshold, 1e-9)
    if ratio < 1.25:
        return AnomalyRisk.LOW
    if ratio < 1.75:
        return AnomalyRisk.MEDIUM
    if ratio < 2.5:
        return AnomalyRisk.HIGH
    return AnomalyRisk.CRITICAL


def detect_anomalies(
    model: Autoencoder,
    preprocessor: Preprocessor,
    windows: list[WindowFeatures],
) -> list[AnomalyRecord]:
    matrix = [[window.features[name] for name in preprocessor.feature_names] for window in windows]
    scaled = preprocessor.transform(matrix)
    scores = score_matrix(model, scaled)
    records: list[AnomalyRecord] = []
    for window, score, scaled_row in zip(windows, scores, scaled, strict=True):
        risk = classify_risk(score, preprocessor.threshold)
        if risk == AnomalyRisk.NORMAL:
            continue
        top = top_deviating_features(preprocessor, scaled_row)
        records.append(
            AnomalyRecord(
                timestamp=window.window_start,
                user_id=window.user_id,
                host_id=window.host_id,
                anomaly_score=score,
                threshold=preprocessor.threshold,
                risk_level=risk,
                top_features=top,
                explanation=make_explanation(risk, top),
                model_version=MODEL_VERSION,
                window_start=window.window_start,
                window_end=window.window_end,
            )
        )
    return sorted(records, key=lambda item: item.anomaly_score, reverse=True)


def top_deviating_features(
    preprocessor: Preprocessor,
    scaled_row: np.ndarray,
    limit: int = 3,
) -> list[str]:
    pairs = sorted(
        zip(preprocessor.feature_names, [abs(float(value)) for value in scaled_row], strict=True),
        key=lambda item: item[1],
        reverse=True,
    )
    return [name for name, _ in pairs[:limit]]


def make_explanation(risk: AnomalyRisk, top_features: list[str]) -> str:
    readable = ", ".join(top_features)
    return (
        f"Statistical anomaly classified as {risk.value}. The strongest deviations from the "
        f"normal synthetic profile are: {readable}. This is not proof of malicious activity."
    )


def summarize_scores(anomalies: list[AnomalyRecord]) -> dict[str, object]:
    by_risk: dict[str, int] = {risk.value: 0 for risk in AnomalyRisk if risk != AnomalyRisk.NORMAL}
    for anomaly in anomalies:
        by_risk[anomaly.risk_level.value] = by_risk.get(anomaly.risk_level.value, 0) + 1
    max_score = max((item.anomaly_score for item in anomalies), default=0.0)
    latest = max((item.timestamp for item in anomalies), default=None)
    return {
        "anomaly_count": len(anomalies),
        "by_risk": by_risk,
        "max_score": max_score,
        "latest_anomaly": latest.isoformat() if isinstance(latest, datetime) else None,
    }
