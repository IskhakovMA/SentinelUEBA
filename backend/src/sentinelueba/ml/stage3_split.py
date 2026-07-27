from __future__ import annotations

import hashlib
import json
from dataclasses import asdict, dataclass
from datetime import datetime
from typing import Any

from sentinelueba.features.windows import FEATURE_NAMES, FEATURE_SCHEMA_VERSION
from sentinelueba.telemetry.synthetic import scenario_manifest_for_start

SPLIT_PLAN_VERSION = "split-plan-v1"


class SplitPlanError(ValueError):
    pass


@dataclass(frozen=True)
class SplitPart:
    name: str
    window_ids: list[str]
    start: str | None
    end: str | None
    count: int


@dataclass(frozen=True)
class SplitPlan:
    split_id: str
    split_strategy: str
    split_plan_version: str
    dataset_id: str
    dataset_manifest_sha256: str
    dataset_kind: str
    profile: dict[str, str]
    feature_schema_version: str
    feature_names: list[str]
    train: SplitPart
    calibration: SplitPart
    test: SplitPart
    scenario_window_ids: list[str]
    manifest_sha256: str

    def to_manifest(self) -> dict[str, Any]:
        return asdict(self)


def create_split_plan(
    rows: list[dict[str, Any]],
    manifest: dict[str, Any],
    *,
    dataset_manifest_sha256: str,
) -> SplitPlan:
    if manifest.get("feature_names") != FEATURE_NAMES:
        raise SplitPlanError("feature names/order mismatch")
    if manifest.get("feature_schema_version") != FEATURE_SCHEMA_VERSION:
        raise SplitPlanError("feature schema mismatch")
    ordered = sorted(rows, key=lambda row: (str(row["window_start"]), str(row["window_id"])))
    if [row["window_id"] for row in ordered] != [row["window_id"] for row in rows]:
        raise SplitPlanError("snapshot rows must already be chronological")
    if len({str(row["window_id"]) for row in ordered}) != len(ordered):
        raise SplitPlanError("duplicate window id in snapshot rows")
    dataset_kind = str(manifest["dataset_kind"])
    if dataset_kind == "synthetic":
        return _synthetic_split(ordered, manifest, dataset_manifest_sha256)
    if dataset_kind == "real":
        return _real_split(ordered, manifest, dataset_manifest_sha256)
    raise SplitPlanError("dataset_kind must be synthetic or real")


def split_matrices(
    rows: list[dict[str, Any]],
    split: SplitPlan,
) -> tuple[list[list[float]], list[list[float]], list[list[float]]]:
    by_id = {str(row["window_id"]): row for row in rows}
    return (
        _matrix([by_id[window_id] for window_id in split.train.window_ids]),
        _matrix([by_id[window_id] for window_id in split.calibration.window_ids]),
        _matrix([by_id[window_id] for window_id in split.test.window_ids]),
    )


def split_rows(
    rows: list[dict[str, Any]],
    split: SplitPlan,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]], list[dict[str, Any]]]:
    by_id = {str(row["window_id"]): row for row in rows}
    return (
        [by_id[window_id] for window_id in split.train.window_ids],
        [by_id[window_id] for window_id in split.calibration.window_ids],
        [by_id[window_id] for window_id in split.test.window_ids],
    )


def _synthetic_split(
    rows: list[dict[str, Any]],
    manifest: dict[str, Any],
    dataset_manifest_sha256: str,
) -> SplitPlan:
    start = datetime.fromisoformat(str(manifest["start"]))
    scenario_manifest = scenario_manifest_for_start(start)
    scenario_starts = {item["window_start"] for item in scenario_manifest}
    first_scenario_start = min(scenario_starts)
    boundary = next(
        (
            index
            for index, row in enumerate(rows)
            if str(row["window_start"]) >= first_scenario_start
        ),
        None,
    )
    if boundary is None:
        raise SplitPlanError("synthetic snapshot does not contain scenario windows")
    normal_pool = rows[:boundary]
    test_rows = rows[boundary:]
    scenario_ids = [
        str(row["window_id"]) for row in test_rows if str(row["window_start"]) in scenario_starts
    ]
    if len(scenario_ids) != 5:
        raise SplitPlanError("synthetic split requires five scenario windows in test")
    train_count = int(len(normal_pool) * 0.70)
    calibration_count = len(normal_pool) - train_count
    if train_count < 32 or calibration_count < 12 or len(test_rows) < 12:
        raise SplitPlanError("not enough pre-scenario windows for leakage-safe synthetic split")
    return _build_plan(
        rows,
        manifest,
        dataset_manifest_sha256,
        strategy="chronological-synthetic-scenario-boundary-70-30-test",
        train_rows=normal_pool[:train_count],
        calibration_rows=normal_pool[train_count:],
        test_rows=test_rows,
        scenario_window_ids=scenario_ids,
    )


def _real_split(
    rows: list[dict[str, Any]],
    manifest: dict[str, Any],
    dataset_manifest_sha256: str,
) -> SplitPlan:
    good = [row for row in rows if row.get("quality_status") == "good"]
    train_count = int(len(good) * 0.70)
    calibration_count = int(len(good) * 0.15)
    test_count = len(good) - train_count - calibration_count
    if train_count < 32 or calibration_count < 12 or test_count < 12:
        raise SplitPlanError(
            "not enough real good windows for split; need train>=32, calibration>=12, test>=12"
        )
    return _build_plan(
        good,
        manifest,
        dataset_manifest_sha256,
        strategy="chronological-real-70-15-15-good-only",
        train_rows=good[:train_count],
        calibration_rows=good[train_count : train_count + calibration_count],
        test_rows=good[train_count + calibration_count :],
        scenario_window_ids=[],
    )


def _build_plan(
    rows: list[dict[str, Any]],
    manifest: dict[str, Any],
    dataset_manifest_sha256: str,
    *,
    strategy: str,
    train_rows: list[dict[str, Any]],
    calibration_rows: list[dict[str, Any]],
    test_rows: list[dict[str, Any]],
    scenario_window_ids: list[str],
) -> SplitPlan:
    parts = [
        _part("train", train_rows),
        _part("calibration", calibration_rows),
        _part("test", test_rows),
    ]
    all_ids = [window_id for part in parts for window_id in part.window_ids]
    if len(set(all_ids)) != len(all_ids):
        raise SplitPlanError("train/calibration/test splits overlap")
    if all_ids != [str(row["window_id"]) for row in rows]:
        raise SplitPlanError("split does not preserve chronological row order")
    profile = dict(manifest["profile"])
    base = {
        "split_plan_version": SPLIT_PLAN_VERSION,
        "split_strategy": strategy,
        "dataset_id": manifest["dataset_id"],
        "dataset_manifest_sha256": dataset_manifest_sha256,
        "dataset_kind": manifest["dataset_kind"],
        "profile": profile,
        "feature_schema_version": FEATURE_SCHEMA_VERSION,
        "feature_names": FEATURE_NAMES,
        "train": asdict(parts[0]),
        "calibration": asdict(parts[1]),
        "test": asdict(parts[2]),
        "scenario_window_ids": scenario_window_ids,
    }
    manifest_sha = _sha(base)
    split_id = f"split-{manifest_sha[:16]}"
    return SplitPlan(
        split_id=split_id,
        split_strategy=strategy,
        split_plan_version=SPLIT_PLAN_VERSION,
        dataset_id=str(manifest["dataset_id"]),
        dataset_manifest_sha256=dataset_manifest_sha256,
        dataset_kind=str(manifest["dataset_kind"]),
        profile=profile,
        feature_schema_version=FEATURE_SCHEMA_VERSION,
        feature_names=FEATURE_NAMES.copy(),
        train=parts[0],
        calibration=parts[1],
        test=parts[2],
        scenario_window_ids=scenario_window_ids,
        manifest_sha256=manifest_sha,
    )


def _part(name: str, rows: list[dict[str, Any]]) -> SplitPart:
    return SplitPart(
        name=name,
        window_ids=[str(row["window_id"]) for row in rows],
        start=str(rows[0]["window_start"]) if rows else None,
        end=str(rows[-1]["window_end"]) if rows else None,
        count=len(rows),
    )


def _matrix(rows: list[dict[str, Any]]) -> list[list[float]]:
    return [[float(row[name]) for name in FEATURE_NAMES] for row in rows]


def _sha(payload: dict[str, Any]) -> str:
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(canonical).hexdigest()
