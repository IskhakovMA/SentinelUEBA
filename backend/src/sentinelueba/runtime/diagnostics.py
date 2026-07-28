from __future__ import annotations

import json
import os
import socket
import sqlite3
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from sentinelueba.collectors.manager import get_manager
from sentinelueba.config import Settings
from sentinelueba.runtime.build_info import get_build_info
from sentinelueba.runtime.control import read_status
from sentinelueba.runtime.installation import verify_installation
from sentinelueba.runtime.paths import RuntimePaths
from sentinelueba.storage.sqlite import DB_SCHEMA_VERSION, SQLiteStorage


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

    try:
        schema_status = inspect_schema_version(paths.database_path)
        migration_required = schema_status < DB_SCHEMA_VERSION
        checks.append(
            {
                "name": "sqlite_schema",
                "status": "degraded" if migration_required else "healthy",
                "schema_version": schema_status,
                "migration_required": migration_required,
            }
        )
        if migration_required:
            status = "degraded"
    except Exception as exc:
        status = "failed"
        checks.append(
            {
                "name": "sqlite_schema",
                "status": "failed",
                "error_class": exc.__class__.__name__,
            }
        )

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
    settings = Settings(
        data_dir=paths.data_dir,
        database_path=paths.database_path,
        model_dir=paths.model_dir,
    )
    checks.append(
        {
            "name": "collectors",
            "status": "healthy",
            "capabilities": len(get_manager(settings).capabilities()),
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
    if not paths.database_path.exists():
        return {"created": False, "reason": "database missing"}
    version = inspect_schema_version(paths.database_path)
    if version >= DB_SCHEMA_VERSION:
        return {"created": False, "reason": "migration not required", "schema_version": version}
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
        "schema_version": version,
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
        "schema_version": version,
        "backup": Path(backup_path.name).as_posix(),
    }


def inspect_schema_version(database_path: Path) -> int:
    if not database_path.exists():
        return 0
    try:
        with sqlite3.connect(database_path) as conn:
            exists = conn.execute(
                "SELECT 1 FROM sqlite_master WHERE type='table' AND name='schema_version'"
            ).fetchone()
            if exists is None:
                return 0
            row = conn.execute("SELECT MAX(version) FROM schema_version").fetchone()
            return int(row[0]) if row and row[0] is not None else 0
    except sqlite3.DatabaseError:
        return 0


def migrate_with_backup(paths: RuntimePaths) -> dict[str, object]:
    version = inspect_schema_version(paths.database_path)
    if version >= DB_SCHEMA_VERSION:
        return {"migration_required": False, "schema_version": version, "backup_created": False}
    backup = backup_before_migration(paths)
    try:
        SQLiteStorage(paths.database_path).initialize()
        final = SQLiteStorage(paths.database_path).status()["schema_version"]
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


def _apply_backup_retention(backups_dir: Path, *, keep: int) -> None:
    backups = sorted(
        backups_dir.glob(f"sentinelueba-before-v{DB_SCHEMA_VERSION}-*.sqlite3"),
        key=lambda path: path.stat().st_mtime,
        reverse=True,
    )
    for backup in backups[keep:]:
        backup.unlink(missing_ok=True)
        backup.with_suffix(".json").unlink(missing_ok=True)
