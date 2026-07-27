from __future__ import annotations

from dataclasses import dataclass
from statistics import mean, median, pstdev
from typing import Any, cast

import numpy as np

CALIBRATION_METHOD_VERSION = "calibration-quantile-v1"


class CalibrationError(ValueError):
    pass


@dataclass(frozen=True)
class ThresholdCalibration:
    method_version: str
    target_false_positive_rate: float
    quantile_method: str
    minimum_calibration_size: int
    calibration_score_count: int
    score_minimum: float
    score_maximum: float
    score_median: float
    score_mean: float
    score_standard_deviation: float
    selected_quantile: float
    threshold: float
    achieved_calibration_flagged_rate: float

    def to_dict(self) -> dict[str, Any]:
        return self.__dict__.copy()


class ThresholdCalibrator:
    def __init__(
        self,
        *,
        target_false_positive_rate: float = 0.05,
        quantile_method: str = "higher",
        minimum_calibration_size: int = 12,
    ) -> None:
        if not 0 < target_false_positive_rate < 1:
            raise CalibrationError("target false-positive rate must be between 0 and 1")
        self.target_false_positive_rate = target_false_positive_rate
        self.quantile_method = quantile_method
        self.minimum_calibration_size = minimum_calibration_size

    def calibrate(self, scores: list[float]) -> ThresholdCalibration:
        finite_scores = [float(score) for score in scores if np.isfinite(score)]
        if len(finite_scores) != len(scores):
            raise CalibrationError("calibration scores contain NaN or Infinity")
        if len(finite_scores) < self.minimum_calibration_size:
            raise CalibrationError(
                f"at least {self.minimum_calibration_size} calibration scores are required"
            )
        quantile = 1.0 - self.target_false_positive_rate
        threshold = float(
            np.quantile(
                np.asarray(finite_scores, dtype=np.float64),
                quantile,
                method=cast(Any, self.quantile_method),
            )
        )
        flagged = sum(1 for score in finite_scores if score >= threshold)
        return ThresholdCalibration(
            method_version=CALIBRATION_METHOD_VERSION,
            target_false_positive_rate=self.target_false_positive_rate,
            quantile_method=self.quantile_method,
            minimum_calibration_size=self.minimum_calibration_size,
            calibration_score_count=len(finite_scores),
            score_minimum=min(finite_scores),
            score_maximum=max(finite_scores),
            score_median=median(finite_scores),
            score_mean=mean(finite_scores),
            score_standard_deviation=pstdev(finite_scores),
            selected_quantile=quantile,
            threshold=threshold,
            achieved_calibration_flagged_rate=flagged / len(finite_scores),
        )
