from __future__ import annotations

import hashlib
import json
import math
import re
import shutil
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from uuid import uuid4

import pyarrow as pa
import pyarrow.parquet as pq

from sentinelueba import __version__
from sentinelueba.features.windows import FEATURE_NAMES, FEATURE_SCHEMA_VERSION
from sentinelueba.storage.sqlite import SQLiteStorage

MANIFEST_VERSION = "dataset-manifest-v1"
DATASET_ID_PATTERN = re.compile(r"^(synthetic|real)-[0-9]{14}-[a-f0-9]{8}$")


class DatasetSnapshotError(ValueError):
    pass


class SnapshotVerificationError(DatasetSnapshotError):
    pass


class DatasetSnapshotService:
    def __init__(self, storage: SQLiteStorage, data_dir: Path) -> None:
        self.storage = storage
        self.datasets_dir = data_dir / "datasets"
        self.datasets_dir.mkdir(parents=True, exist_ok=True)

    def create(
        self,
        dataset_kind: str,
        *,
        quality_statuses: set[str] | None = None,
    ) -> dict[str, Any]:
        statuses = quality_statuses or (
            {"good", "degraded"} if dataset_kind == "synthetic" else {"good"}
        )
        windows = self.storage.list_feature_windows(
            dataset_kind=dataset_kind,
            quality_status=statuses,
        )
        if not windows:
            raise DatasetSnapshotError(f"no {dataset_kind} feature windows match quality filters")
        profiles = sorted({(window["user_id"], window["host_id"]) for window in windows})
        if len(profiles) != 1:
            raise DatasetSnapshotError("dataset snapshot requires exactly one user+host profile")
        timestamp = datetime.now(UTC).strftime("%Y%m%d%H%M%S")
        dataset_id = f"{dataset_kind}-{timestamp}-{uuid4().hex[:8]}"
        dataset_dir = self._dataset_dir(dataset_id, must_exist=False)
        tmp_dir = self.datasets_dir / f".tmp-{dataset_id}"
        if dataset_dir.exists() or tmp_dir.exists():
            raise DatasetSnapshotError("dataset snapshot already exists")
        try:
            tmp_dir.mkdir(parents=True)
            parquet_path = tmp_dir / "features.parquet"
            rows = [self._snapshot_row(window, index) for index, window in enumerate(windows)]
            table = pa.Table.from_pylist(rows)
            pq.write_table(table, parquet_path)
            parquet_sha = sha256_file(parquet_path)
            profile = {"user_id": profiles[0][0], "host_id": profiles[0][1]}
            all_windows = [
                window
                for window in self.storage.list_feature_windows(dataset_kind=dataset_kind)
                if window["user_id"] == profile["user_id"]
                and window["host_id"] == profile["host_id"]
                and windows[0]["window_start"]
                <= window["window_start"]
                <= windows[-1]["window_start"]
            ]
            manifest = {
                "manifest_version": MANIFEST_VERSION,
                "dataset_id": dataset_id,
                "dataset_kind": dataset_kind,
                "created_at": datetime.now(UTC).isoformat(),
                "application_version": __version__,
                "event_schema_versions": self._event_schema_versions(
                    dataset_kind,
                    profile,
                    windows[0]["window_start"],
                    windows[-1]["window_end"],
                ),
                "feature_schema_version": FEATURE_SCHEMA_VERSION,
                "profile": profile,
                "start": windows[0]["window_start"],
                "end": windows[-1]["window_end"],
                "window_size_minutes": windows[0]["window_size_minutes"],
                "window_count": len(windows),
                "quality_counts": self._quality_counts(windows),
                "materialized_quality_counts": self._quality_counts(all_windows),
                "included_quality_counts": self._quality_counts(windows),
                "quality_filters": sorted(statuses),
                "feature_names": FEATURE_NAMES,
                "source_event_counts": self._event_counts(windows),
                "collector_coverage_summary": self._coverage_summary(windows),
                "synthetic_scenario_metadata": (
                    [] if dataset_kind != "synthetic" else ["demo-evaluation-only"]
                ),
                "parquet_sha256": parquet_sha,
            }
            manifest_path = tmp_dir / "manifest.json"
            manifest_path.write_text(json.dumps(manifest, indent=2, sort_keys=True))
            manifest_sha = sha256_file(manifest_path)
            (tmp_dir / "checksums.sha256").write_text(
                f"{parquet_sha}  features.parquet\n{manifest_sha}  manifest.json\n"
            )
            self._verify_files(dataset_id, tmp_dir, manifest, registry=None)
            tmp_dir.rename(dataset_dir)
            self.storage.register_dataset_snapshot(manifest, manifest_sha)
            self.verify(dataset_id)
            return {"dataset_id": dataset_id, "manifest_sha256": manifest_sha, "manifest": manifest}
        except Exception:
            if tmp_dir.exists():
                shutil.rmtree(tmp_dir)
            if dataset_dir.exists() and self.storage.get_dataset_snapshot(dataset_id) is None:
                shutil.rmtree(dataset_dir)
            raise

    def list_snapshots(self, dataset_kind: str | None = None) -> list[dict[str, Any]]:
        return self.storage.list_dataset_snapshots(dataset_kind)

    def show(self, dataset_id: str) -> dict[str, Any]:
        manifest = self._read_manifest(dataset_id)
        return {"dataset_id": dataset_id, "manifest": manifest}

    def verify(self, dataset_id: str) -> dict[str, Any]:
        dataset_dir = self._dataset_dir(dataset_id)
        manifest = self._read_manifest(dataset_id)
        registry = self.storage.get_dataset_snapshot(dataset_id)
        table = self._verify_files(dataset_id, dataset_dir, manifest, registry=registry)
        return {
            "dataset_id": dataset_id,
            "verified": True,
            "parquet_sha256": manifest["parquet_sha256"],
            "manifest_sha256": sha256_file(dataset_dir / "manifest.json"),
            "window_count": table.num_rows,
        }

    def load_matrix(
        self,
        dataset_id: str,
    ) -> tuple[list[list[float]], dict[str, Any], list[dict[str, Any]]]:
        verification = self.verify(dataset_id)
        manifest = self._read_manifest(dataset_id)
        if manifest.get("feature_schema_version") != FEATURE_SCHEMA_VERSION:
            raise SnapshotVerificationError("incompatible feature schema")
        table = pq.read_table(self._dataset_dir(dataset_id) / "features.parquet")
        rows = table.to_pylist()
        matrix = [[float(row[name]) for name in FEATURE_NAMES] for row in rows]
        manifest["verification"] = verification
        return matrix, manifest, rows

    def latest_dataset_id(self, dataset_kind: str) -> str | None:
        snapshots = self.storage.list_dataset_snapshots(dataset_kind)
        return str(snapshots[0]["dataset_id"]) if snapshots else None

    def _read_manifest(self, dataset_id: str) -> dict[str, Any]:
        path = self._dataset_dir(dataset_id) / "manifest.json"
        if not path.exists():
            raise SnapshotVerificationError("manifest.json is missing")
        try:
            payload = json.loads(path.read_text())
        except json.JSONDecodeError as exc:
            raise SnapshotVerificationError("manifest.json is damaged") from exc
        if not isinstance(payload, dict) or payload.get("dataset_id") != dataset_id:
            raise SnapshotVerificationError("manifest dataset id mismatch")
        return payload

    def _dataset_dir(self, dataset_id: str, *, must_exist: bool = True) -> Path:
        if not DATASET_ID_PATTERN.fullmatch(dataset_id):
            raise SnapshotVerificationError("unsafe dataset id")
        path = (self.datasets_dir / dataset_id).resolve()
        datasets_root = self.datasets_dir.resolve()
        if path.parent != datasets_root:
            raise SnapshotVerificationError("dataset path escapes datasets directory")
        if must_exist and not path.exists():
            raise SnapshotVerificationError("dataset directory is missing")
        return path

    def _snapshot_row(self, window: dict[str, Any], index: int) -> dict[str, Any]:
        row = {
            "row_index": index,
            "window_id": window["window_id"],
            "window_start": window["window_start"],
            "window_end": window["window_end"],
            "user_id": window["user_id"],
            "host_id": window["host_id"],
            "dataset_kind": window["dataset_kind"],
            "quality_status": window["quality_status"],
            "event_count": window["event_count"],
        }
        row.update({name: float(window["features"][name]) for name in FEATURE_NAMES})
        return row

    def _verify_files(
        self,
        dataset_id: str,
        dataset_dir: Path,
        manifest: dict[str, Any],
        *,
        registry: dict[str, Any] | None,
    ) -> pa.Table:
        if manifest.get("manifest_version") != MANIFEST_VERSION:
            raise SnapshotVerificationError("unsupported manifest version")
        if manifest.get("dataset_id") != dataset_id:
            raise SnapshotVerificationError("manifest dataset id mismatch")
        if manifest.get("feature_schema_version") != FEATURE_SCHEMA_VERSION:
            raise SnapshotVerificationError("incompatible feature schema")
        if manifest.get("feature_names") != FEATURE_NAMES:
            raise SnapshotVerificationError("feature names/order mismatch")
        checksums = self._read_checksums(dataset_dir / "checksums.sha256")
        parquet_path = dataset_dir / "features.parquet"
        manifest_path = dataset_dir / "manifest.json"
        actual_parquet = sha256_file(parquet_path)
        actual_manifest = sha256_file(manifest_path)
        if checksums.get("features.parquet") != actual_parquet:
            raise SnapshotVerificationError("checksums.sha256 Parquet hash mismatch")
        if checksums.get("manifest.json") != actual_manifest:
            raise SnapshotVerificationError("checksums.sha256 manifest hash mismatch")
        if actual_parquet != manifest.get("parquet_sha256"):
            raise SnapshotVerificationError("manifest Parquet SHA-256 mismatch")
        if registry is not None:
            if registry["manifest_sha256"] != actual_manifest:
                raise SnapshotVerificationError("SQLite manifest SHA-256 mismatch")
            if registry["parquet_sha256"] != actual_parquet:
                raise SnapshotVerificationError("SQLite Parquet SHA-256 mismatch")
            if registry["dataset_kind"] != manifest["dataset_kind"]:
                raise SnapshotVerificationError("SQLite dataset kind mismatch")
            if registry["profile"] != manifest["profile"]:
                raise SnapshotVerificationError("SQLite profile mismatch")
            if registry["start"] != manifest["start"] or registry["end"] != manifest["end"]:
                raise SnapshotVerificationError("SQLite dataset range mismatch")
            if int(registry["window_count"]) != int(manifest["window_count"]):
                raise SnapshotVerificationError("SQLite window count mismatch")
            if registry["feature_schema_version"] != manifest["feature_schema_version"]:
                raise SnapshotVerificationError("SQLite feature schema mismatch")
        try:
            table = pq.read_table(parquet_path)
        except Exception as exc:  # noqa: BLE001
            raise SnapshotVerificationError(f"cannot read Parquet: {type(exc).__name__}") from exc
        required = [
            "row_index",
            "window_id",
            "window_start",
            "window_end",
            "user_id",
            "host_id",
            "dataset_kind",
            "quality_status",
            "event_count",
            *FEATURE_NAMES,
        ]
        if table.column_names != required:
            raise SnapshotVerificationError("Parquet columns/order mismatch")
        rows = table.to_pylist()
        if len(rows) != int(manifest["window_count"]):
            raise SnapshotVerificationError("Parquet row count does not match manifest")
        if rows:
            if str(rows[0]["window_start"]) != manifest["start"]:
                raise SnapshotVerificationError("first Parquet window_start mismatch")
            if str(rows[-1]["window_end"]) != manifest["end"]:
                raise SnapshotVerificationError("last Parquet window_end mismatch")
        seen_windows: set[str] = set()
        previous_start = ""
        for index, row in enumerate(rows):
            if int(row["row_index"]) != index:
                raise SnapshotVerificationError("Parquet row_index sequence mismatch")
            if row["window_id"] in seen_windows:
                raise SnapshotVerificationError("duplicate window_id in Parquet")
            seen_windows.add(str(row["window_id"]))
            if row["dataset_kind"] != manifest["dataset_kind"]:
                raise SnapshotVerificationError("row dataset_kind mismatch")
            if (
                row["user_id"] != manifest["profile"]["user_id"]
                or row["host_id"] != manifest["profile"]["host_id"]
            ):
                raise SnapshotVerificationError("row profile mismatch")
            if str(row["window_start"]) < previous_start:
                raise SnapshotVerificationError("Parquet rows are not sorted by window_start")
            previous_start = str(row["window_start"])
            for name in FEATURE_NAMES:
                value = float(row[name])
                if math.isnan(value) or math.isinf(value):
                    raise SnapshotVerificationError("feature contains NaN or Infinity")
        return table

    def _read_checksums(self, path: Path) -> dict[str, str]:
        if not path.exists():
            raise SnapshotVerificationError("checksums.sha256 is missing")
        checksums: dict[str, str] = {}
        for line in path.read_text().splitlines():
            parts = line.split()
            if len(parts) != 2:
                raise SnapshotVerificationError("checksums.sha256 is damaged")
            checksums[parts[1]] = parts[0]
        return checksums

    def _quality_counts(self, windows: list[dict[str, Any]]) -> dict[str, int]:
        return {
            status: sum(1 for window in windows if window["quality_status"] == status)
            for status in ("good", "degraded", "insufficient")
        }

    def _event_counts(self, windows: list[dict[str, Any]]) -> dict[str, int]:
        counts: dict[str, int] = {}
        for window in windows:
            for event_type, count in window["event_counts"].items():
                counts[event_type] = counts.get(event_type, 0) + int(count)
        return counts

    def _event_schema_versions(
        self,
        dataset_kind: str,
        profile: dict[str, str],
        start: str,
        end: str,
    ) -> list[str]:
        rows = self.storage.list_event_rows(
            synthetic=(dataset_kind == "synthetic"),
            start=datetime.fromisoformat(start),
            end=datetime.fromisoformat(end),
        )
        versions = {
            str(row.get("event_schema_version") or row["event"].schema_version)
            for row in rows
            if row["event"].user_id == profile["user_id"]
            and row["event"].host_id == profile["host_id"]
        }
        return sorted(versions)

    def _coverage_summary(self, windows: list[dict[str, Any]]) -> dict[str, Any]:
        coverage = [
            float(window["collector_coverage"].get("heartbeat_coverage", 0.0))
            for window in windows
        ]
        return {
            "avg_heartbeat_coverage": sum(coverage) / len(coverage) if coverage else 0.0,
            "min_heartbeat_coverage": min(coverage, default=0.0),
        }


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    try:
        with path.open("rb") as handle:
            for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                digest.update(chunk)
    except FileNotFoundError as exc:
        raise SnapshotVerificationError(f"{path.name} is missing") from exc
    return digest.hexdigest()
