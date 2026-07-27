from __future__ import annotations

from datetime import datetime

import numpy as np

from sentinelueba.domain.events import AnomalyRecord, AnomalyRisk, WindowFeatures
from sentinelueba.ml.autoencoder import MODEL_VERSION, Autoencoder, Preprocessor, reconstruct_matrix


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
    range_kind: str = "evaluation",
) -> list[AnomalyRecord]:
    matrix = [[window.features[name] for name in preprocessor.feature_names] for window in windows]
    raw = np.asarray(matrix, dtype=np.float32)
    scaled = preprocessor.transform(matrix)
    scores, reconstructed_scaled, residuals = reconstruct_matrix(model, scaled)
    records: list[AnomalyRecord] = []
    for window, score, raw_row, reconstructed_row, residual_row in zip(
        windows,
        scores,
        raw,
        reconstructed_scaled,
        residuals,
        strict=True,
    ):
        risk = classify_risk(score, preprocessor.threshold)
        if risk == AnomalyRisk.NORMAL:
            continue
        contributions = feature_contributions(
            preprocessor,
            raw_row,
            reconstructed_row,
            residual_row,
        )
        top = [str(item["feature_name"]) for item in contributions[:3]]
        records.append(
            AnomalyRecord(
                timestamp=window.window_start,
                user_id=window.user_id,
                host_id=window.host_id,
                anomaly_score=score,
                threshold=preprocessor.threshold,
                risk_level=risk,
                top_features=top,
                feature_contributions=contributions[:5],
                explanation=make_explanation(risk, contributions[:3], preprocessor.dataset_kind),
                model_version=MODEL_VERSION,
                window_start=window.window_start,
                window_end=window.window_end,
                range_kind=range_kind,
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


def feature_contributions(
    preprocessor: Preprocessor,
    raw_row: np.ndarray,
    reconstructed_scaled_row: np.ndarray,
    residual_row: np.ndarray,
) -> list[dict[str, float | str]]:
    mean = np.asarray(preprocessor.mean, dtype=np.float32)
    std = np.asarray(preprocessor.std, dtype=np.float32)
    reconstructed_raw = reconstructed_scaled_row * std + mean
    rows: list[dict[str, float | str]] = []
    for index, feature_name in enumerate(preprocessor.feature_names):
        observed = float(raw_row[index])
        expected = float(reconstructed_raw[index])
        rows.append(
            {
                "feature_name": feature_name,
                "observed_value": observed,
                "expected_value": expected,
                "contribution": float(residual_row[index]),
                "direction": "above" if observed > expected else "below",
            }
        )
    return sorted(rows, key=lambda item: float(item["contribution"]), reverse=True)


def make_explanation(
    risk: AnomalyRisk,
    contributions: list[dict[str, float | str]],
    dataset_kind: str,
) -> str:
    readable = ", ".join(str(item["feature_name"]) for item in contributions)
    profile_name = "real local profile" if dataset_kind == "real" else "synthetic profile"
    return (
        f"Statistical anomaly classified as {risk.value}. The strongest deviations from the "
        f"normal {profile_name} are: {readable}. This is not proof of malicious activity."
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
