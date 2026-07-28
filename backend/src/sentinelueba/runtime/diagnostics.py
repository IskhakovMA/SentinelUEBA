from __future__ import annotations

import json
import os
import socket
import sqlite3
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Literal

from sentinelueba.collectors.base import TelemetryCollector
from sentinelueba.collectors.network import NetworkCollector
from sentinelueba.collectors.process import ProcessCollector
from sentinelueba.collectors.system_metrics import SystemMetricsCollector
from sentinelueba.collectors.windows_auth import WindowsAuthCollector
from sentinelueba.runtime.build_info import get_build_info
from sentinelueba.runtime.control import read_status
from sentinelueba.runtime.installation import verify_installation
from sentinelueba.runtime.paths import RuntimePaths
from sentinelueba.storage.sqlite import DB_SCHEMA_VERSION, SchemaIntegrityError, SQLiteStorage

SchemaInspectionStatus = Literal[
    "missing",
    "older",
    "current_valid",
    "current_corrupt",
    "newer",
    "unreadable",
]


@dataclass(frozen=True)
class SchemaInspectionResult:
    status: SchemaInspectionStatus
    schema_version: int
    migration_required: bool = False
    unsupported_newer_schema: bool = False
    error_class: str | None = None

    def safe_dict(self) -> dict[str, object]:
        payload: dict[str, object] = {
            "inspection_status": self.status,
            "schema_version": self.schema_version,
            "migration_required": self.migration_required,
            "unsupported_newer_schema": self.unsupported_newer_schema,
        }
        if self.error_class is not None:
            payload["error_class"] = self.error_class
        return payload


def port_available(port: int) -> bool:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.settimeout(0.2)
        return sock.connect_ex(("127.0.0.1", port)) != 0


def doctor(paths: RuntimePaths, *, port: int | None = None) -> dict[str, Any]:
    build = get_build_info()
    checks: list[dict[str, object]] = []
    status = "healthy"
    paths.ensure()
    checks.append({"name": "runtime_root", "status": "healthy"})

    schema = inspect_schema(paths.database_path)
    schema_check_status = _doctor_schema_status(schema)
    checks.append({"name": "sqlite_schema", "status": schema_check_status, **schema.safe_dict()})
    if schema_check_status == "failed":
        status = "failed"
    elif schema_check_status == "degraded" and status == "healthy":
        status = "degraded"

    manifest = verify_installation(paths.package_dir) if build.mode == "packaged" else None
    if manifest is not None:
        checks.append({"name": "release_manifest", **manifest.safe_dict()})
        if manifest.status not in {"verified", "unsigned_verified"}:
            status = "failed"

    if port is not None:
        checks.append({"name": "port", "status": "healthy" if port_available(port) else "degraded"})

    host_status = read_status(paths.runtime_dir / "status.json")
    checks.append(
        {
            "name": "host_state",
            "status": host_status.state if host_status is not None else "stopped",
        }
    )
    checks.append(
        {
            "name": "collectors",
            "status": "healthy",
            "capabilities": len(_collector_capabilities_read_only()),
        }
    )
    return {
        "status": status,
        "build": build.safe_dict(),
        "mode": paths.mode,
        "schema_version": DB_SCHEMA_VERSION,
        "checks": checks,
    }


def exit_code(report: dict[str, Any]) -> int:
    status = str(report.get("status", "failed"))
    if status == "healthy":
        return 0
    if status == "degraded":
        return 1
    return 2


def backup_before_migration(paths: RuntimePaths) -> dict[str, object]:
    inspection = inspect_schema(paths.database_path)
    if inspection.status == "missing":
        return {"created": False, "reason": "database missing"}
    if inspection.status == "current_valid":
        return {
            "created": False,
            "reason": "migration not required",
            "schema_version": inspection.schema_version,
        }
    if inspection.status == "newer":
        raise RuntimeError("unsupported newer SQLite schema")
    if inspection.status in {"current_corrupt", "unreadable"}:
        raise RuntimeError("SQLite schema inspection failed")
    paths.backups_dir.mkdir(parents=True, exist_ok=True)
    timestamp = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
    backup_path = paths.backups_dir / (
        f"sentinelueba-before-v{DB_SCHEMA_VERSION}-{timestamp}.sqlite3"
    )
    metadata_path = backup_path.with_suffix(".json")
    with (
        sqlite3.connect(paths.database_path) as source,
        sqlite3.connect(backup_path) as destination,
    ):
        source.backup(destination)
        destination.execute("PRAGMA wal_checkpoint(TRUNCATE)")
        integrity = destination.execute("PRAGMA integrity_check").fetchone()[0]
        if integrity != "ok":
            raise RuntimeError("SQLite backup integrity check failed")
    with backup_path.open("r+b") as handle:
        os.fsync(handle.fileno())
    metadata = {
        "schema_version": inspection.schema_version,
        "target_schema_version": DB_SCHEMA_VERSION,
        "created_at": timestamp,
        "database": paths.database_path.name,
        "backup": backup_path.name,
    }
    metadata_path.write_text(json.dumps(metadata, sort_keys=True), encoding="utf-8")
    with metadata_path.open("r+b") as handle:
        os.fsync(handle.fileno())
    _apply_backup_retention(paths.backups_dir, keep=5)
    return {
        "created": True,
        "schema_version": inspection.schema_version,
        "backup": Path(backup_path.name).as_posix(),
    }


def inspect_schema_version(database_path: Path) -> int:
    return inspect_schema(database_path).schema_version


def inspect_schema(database_path: Path) -> SchemaInspectionResult:
    if not database_path.exists():
        return SchemaInspectionResult("missing", 0, migration_required=True)
    try:
        database_uri = f"file:{database_path}?mode=ro"
        conn = sqlite3.connect(database_uri, uri=True)
        try:
            conn.row_factory = sqlite3.Row
            integrity = conn.execute("PRAGMA integrity_check").fetchone()
            if integrity is None or integrity[0] != "ok":
                return SchemaInspectionResult(
                    "unreadable",
                    0,
                    error_class="DatabaseError",
                )
            exists = conn.execute(
                "SELECT 1 FROM sqlite_master WHERE type='table' AND name='schema_version'"
            ).fetchone()
            if exists is None:
                return SchemaInspectionResult("missing", 0, migration_required=True)
            row = conn.execute("SELECT MAX(version) FROM schema_version").fetchone()
            version = int(row[0]) if row and row[0] is not None else 0
        finally:
            conn.close()
    except sqlite3.DatabaseError as exc:
        return SchemaInspectionResult("unreadable", 0, error_class=exc.__class__.__name__)
    if version < DB_SCHEMA_VERSION:
        return SchemaInspectionResult("older", version, migration_required=True)
    if version > DB_SCHEMA_VERSION:
        return SchemaInspectionResult(
            "newer",
            version,
            unsupported_newer_schema=True,
        )
    try:
        SQLiteStorage(database_path).verify_schema_integrity()
    except SchemaIntegrityError as exc:
        return SchemaInspectionResult(
            "current_corrupt",
            version,
            error_class=exc.__class__.__name__,
        )
    except sqlite3.DatabaseError as exc:
        return SchemaInspectionResult("unreadable", version, error_class=exc.__class__.__name__)
    return SchemaInspectionResult("current_valid", version)


def migrate_with_backup(paths: RuntimePaths) -> dict[str, object]:
    inspection = inspect_schema(paths.database_path)
    if inspection.status == "newer":
        return {
            "migration_required": False,
            "status": "failed",
            "schema_version": inspection.schema_version,
            "unsupported_newer_schema": True,
            "error_class": "UnsupportedNewerSchema",
        }
    if inspection.status in {"current_corrupt", "unreadable"}:
        return {
            "migration_required": inspection.migration_required,
            "status": "failed",
            "schema_version": inspection.schema_version,
            "error_class": inspection.error_class or "DatabaseError",
        }
    if inspection.status == "current_valid":
        try:
            SQLiteStorage(paths.database_path).verify_schema_integrity()
        except Exception as exc:
            return {
                "migration_required": False,
                "status": "failed",
                "schema_version": inspection.schema_version,
                "error_class": exc.__class__.__name__,
            }
        return {
            "migration_required": False,
            "status": "success",
            "schema_version": inspection.schema_version,
            "backup_created": False,
        }
    backup = backup_before_migration(paths)
    try:
        SQLiteStorage(paths.database_path).initialize()
        storage = SQLiteStorage(paths.database_path)
        storage.verify_schema_integrity()
        final = storage.status()["schema_version"]
    except Exception as exc:
        return {
            "migration_required": True,
            "status": "failed",
            "backup": backup,
            "error_class": exc.__class__.__name__,
            "recovery": (
                "Keep the backup and inspect logs before retrying; "
                "no destructive restore was performed."
            ),
        }
    return {
        "migration_required": True,
        "status": "success",
        "schema_version": final,
        "backup": backup,
    }


def _doctor_schema_status(inspection: SchemaInspectionResult) -> str:
    if inspection.status == "current_valid":
        return "healthy"
    if inspection.status in {"missing", "older"}:
        return "degraded"
    return "failed"


def _collector_capabilities_read_only() -> list[dict[str, object]]:
    collectors: list[TelemetryCollector] = [
        ProcessCollector("doctor-user", "doctor-host"),
        NetworkCollector("doctor-user", "doctor-host"),
        SystemMetricsCollector("doctor-user", "doctor-host"),
        WindowsAuthCollector("doctor-user", "doctor-host", None),
    ]
    return [collector.check_availability().__dict__ for collector in collectors]


def _apply_backup_retention(backups_dir: Path, *, keep: int) -> None:
    backups = sorted(
        backups_dir.glob(f"sentinelueba-before-v{DB_SCHEMA_VERSION}-*.sqlite3"),
        key=lambda path: path.stat().st_mtime,
        reverse=True,
    )
    for backup in backups[keep:]:
        backup.unlink(missing_ok=True)
        backup.with_suffix(".json").unlink(missing_ok=True)
