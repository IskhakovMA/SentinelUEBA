from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from uuid import uuid4

import pyarrow as pa
import pyarrow.parquet as pq

from sentinelueba import __version__
from sentinelueba.features.windows import FEATURE_NAMES, FEATURE_SCHEMA_VERSION
from sentinelueba.storage.sqlite import SQLiteStorage
from sentinelueba.validation import EVENT_SCHEMA_VERSION

MANIFEST_VERSION = "dataset-manifest-v1"


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
        dataset_dir = self.datasets_dir / dataset_id
        if dataset_dir.exists():
            raise DatasetSnapshotError("dataset snapshot already exists")
        dataset_dir.mkdir(parents=True)
        parquet_path = dataset_dir / "features.parquet"
        rows = []
        for window in windows:
            row = {
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
            rows.append(row)
        table = pa.Table.from_pylist(rows)
        pq.write_table(table, parquet_path)
        parquet_sha = sha256_file(parquet_path)
        counts = self._quality_counts(windows)
        manifest = {
            "manifest_version": MANIFEST_VERSION,
            "dataset_id": dataset_id,
            "dataset_kind": dataset_kind,
            "created_at": datetime.now(UTC).isoformat(),
            "application_version": __version__,
            "event_schema_versions": [EVENT_SCHEMA_VERSION],
            "feature_schema_version": FEATURE_SCHEMA_VERSION,
            "profile": {"user_id": profiles[0][0], "host_id": profiles[0][1]},
            "start": windows[0]["window_start"],
            "end": windows[-1]["window_end"],
            "window_size_minutes": windows[0]["window_size_minutes"],
            "window_count": len(windows),
            "quality_counts": counts,
            "quality_filters": sorted(statuses),
            "feature_names": FEATURE_NAMES,
            "source_event_counts": self._event_counts(windows),
            "collector_coverage_summary": self._coverage_summary(windows),
            "synthetic_scenario_metadata": (
                [] if dataset_kind != "synthetic" else ["demo-evaluation-only"]
            ),
            "parquet_sha256": parquet_sha,
        }
        manifest_path = dataset_dir / "manifest.json"
        manifest_path.write_text(json.dumps(manifest, indent=2, sort_keys=True))
        manifest_sha = sha256_file(manifest_path)
        (dataset_dir / "checksums.sha256").write_text(
            f"{parquet_sha}  features.parquet\n{manifest_sha}  manifest.json\n"
        )
        self.storage.register_dataset_snapshot(manifest, manifest_sha)
        return {"dataset_id": dataset_id, "manifest_sha256": manifest_sha, "manifest": manifest}

    def list_snapshots(self, dataset_kind: str | None = None) -> list[dict[str, Any]]:
        return self.storage.list_dataset_snapshots(dataset_kind)

    def show(self, dataset_id: str) -> dict[str, Any]:
        manifest = self._read_manifest(dataset_id)
        return {"dataset_id": dataset_id, "manifest": manifest}

    def verify(self, dataset_id: str) -> dict[str, Any]:
        dataset_dir = self.datasets_dir / dataset_id
        manifest = self._read_manifest(dataset_id)
        parquet_path = dataset_dir / "features.parquet"
        checksums_path = dataset_dir / "checksums.sha256"
        if not checksums_path.exists():
            raise SnapshotVerificationError("checksums.sha256 is missing")
        actual_parquet = sha256_file(parquet_path)
        if actual_parquet != manifest.get("parquet_sha256"):
            raise SnapshotVerificationError("Parquet SHA-256 mismatch")
        try:
            table = pq.read_table(parquet_path)
        except Exception as exc:  # noqa: BLE001
            raise SnapshotVerificationError(f"cannot read Parquet: {type(exc).__name__}") from exc
        if table.num_rows != int(manifest["window_count"]):
            raise SnapshotVerificationError("Parquet row count does not match manifest")
        return {
            "dataset_id": dataset_id,
            "verified": True,
            "parquet_sha256": actual_parquet,
            "window_count": table.num_rows,
        }

    def load_matrix(self, dataset_id: str) -> tuple[list[list[float]], dict[str, Any]]:
        verification = self.verify(dataset_id)
        manifest = self._read_manifest(dataset_id)
        if manifest.get("feature_schema_version") != FEATURE_SCHEMA_VERSION:
            raise SnapshotVerificationError("incompatible feature schema")
        table = pq.read_table(self.datasets_dir / dataset_id / "features.parquet")
        rows = table.to_pylist()
        matrix = [[float(row[name]) for name in FEATURE_NAMES] for row in rows]
        manifest["verification"] = verification
        return matrix, manifest

    def latest_dataset_id(self, dataset_kind: str) -> str | None:
        snapshots = self.storage.list_dataset_snapshots(dataset_kind)
        return str(snapshots[0]["dataset_id"]) if snapshots else None

    def _read_manifest(self, dataset_id: str) -> dict[str, Any]:
        path = self.datasets_dir / dataset_id / "manifest.json"
        if not path.exists():
            raise SnapshotVerificationError("manifest.json is missing")
        try:
            payload = json.loads(path.read_text())
        except json.JSONDecodeError as exc:
            raise SnapshotVerificationError("manifest.json is damaged") from exc
        if not isinstance(payload, dict) or payload.get("dataset_id") != dataset_id:
            raise SnapshotVerificationError("manifest dataset id mismatch")
        return payload

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
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()
