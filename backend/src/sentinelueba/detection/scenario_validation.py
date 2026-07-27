from __future__ import annotations

from datetime import datetime
from typing import Any

RISK_ORDER = {"low": 1, "medium": 2, "high": 3, "critical": 4}


def validate_demo_scenarios(
    manifest: list[dict[str, str]],
    anomalies: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    results: list[dict[str, Any]] = []
    for scenario in manifest:
        expected_start = datetime.fromisoformat(scenario["window_start"])
        expected_end = datetime.fromisoformat(scenario["window_end"])
        matches = [
            anomaly
            for anomaly in anomalies
            if _same_window(anomaly, expected_start, expected_end)
        ]
        best_score = max((float(item["anomaly_score"]) for item in matches), default=0.0)
        max_risk = max(
            (str(item["risk_level"]) for item in matches),
            key=lambda risk: RISK_ORDER.get(risk, 0),
            default="none",
        )
        results.append(
            {
                "scenario_name": scenario["name"],
                "expected_window_start": scenario["window_start"],
                "expected_window_end": scenario["window_end"],
                "detected": bool(matches),
                "match_count": len(matches),
                "best_anomaly_score": best_score,
                "max_risk_level": max_risk,
                "matching_window_ids": [
                    f"{item['window_start']}::{item['window_end']}" for item in matches
                ],
            }
        )
    return results


def _same_window(
    anomaly: dict[str, Any],
    expected_start: datetime,
    expected_end: datetime,
) -> bool:
    window_start = datetime.fromisoformat(str(anomaly["window_start"]).replace("Z", "+00:00"))
    window_end = datetime.fromisoformat(str(anomaly["window_end"]).replace("Z", "+00:00"))
    return window_start == expected_start and window_end == expected_end
