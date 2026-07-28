from __future__ import annotations

import socket
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

    storage = SQLiteStorage(paths.database_path)
    try:
        storage.initialize()
        schema_status = storage.status().get("schema_version")
        checks.append(
            {
                "name": "sqlite_schema",
                "status": "healthy",
                "schema_version": schema_status,
            }
        )
        if schema_status != DB_SCHEMA_VERSION:
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
    storage = SQLiteStorage(paths.database_path)
    try:
        with storage.connect() as conn:
            row = conn.execute("SELECT MAX(version) FROM schema_version").fetchone()
            version = int(row[0]) if row and row[0] is not None else 0
    except Exception:
        version = 0
    if version >= DB_SCHEMA_VERSION:
        return {"created": False, "reason": "migration not required", "schema_version": version}
    paths.backups_dir.mkdir(parents=True, exist_ok=True)
    backup_path = paths.backups_dir / f"sentinelueba-before-v{DB_SCHEMA_VERSION}.sqlite3"
    backup_path.write_bytes(paths.database_path.read_bytes())
    return {
        "created": True,
        "schema_version": version,
        "backup": Path(backup_path.name).as_posix(),
    }
