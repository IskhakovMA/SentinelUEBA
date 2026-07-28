from __future__ import annotations

import shutil
from datetime import UTC, datetime
from pathlib import Path

from sentinelueba.runtime.paths import RuntimePaths, reject_escape

DENY_NAMES = {
    "identity.secret",
    "control.token",
    "host.lock",
    "status.json",
    "config.json",
    "build-info.json",
}
DENY_SUFFIXES = {".env", ".pfx", ".pem", ".key"}


def preview_import(source: Path) -> dict[str, object]:
    safe_source = source.expanduser().resolve()
    if not safe_source.exists() or not safe_source.is_dir():
        raise ValueError("source directory is not available")
    files = [
        path.relative_to(safe_source).as_posix()
        for path in sorted(safe_source.rglob("*"))
        if _safe_source_file(path, safe_source)
    ]
    return {"source": "<provided-directory>", "file_count": len(files), "files": files[:50]}


def import_data(source: Path, paths: RuntimePaths, *, confirm: bool) -> dict[str, object]:
    if not confirm:
        raise ValueError("runtime import-data requires --confirm")
    safe_source = source.expanduser().resolve()
    if not safe_source.exists() or not safe_source.is_dir():
        raise ValueError("source directory is not available")
    reject_escape(paths.data_dir, paths.root)
    paths.ensure()
    timestamp = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
    backup_dir = paths.backups_dir / f"import-previous-data-{timestamp}"
    if paths.data_dir.exists() and any(paths.data_dir.iterdir()):
        backup_dir.mkdir(parents=True, exist_ok=True)
        for item in paths.data_dir.iterdir():
            destination = backup_dir / item.name
            if item.is_dir():
                if destination.exists():
                    shutil.rmtree(destination)
                shutil.copytree(item, destination)
            elif item.is_file():
                shutil.copy2(item, destination)
    copied = 0
    rejected = 0
    for path in safe_source.rglob("*"):
        if not _safe_source_file(path, safe_source):
            if path.is_file() or path.is_symlink():
                rejected += 1
            continue
        rel = path.relative_to(safe_source)
        target = paths.data_dir / rel
        reject_escape(target.parent, paths.data_dir)
        target.parent.mkdir(parents=True, exist_ok=True)
        if target.exists():
            continue
        shutil.copy2(path, target)
        copied += 1
    return {
        "imported": copied,
        "rejected": rejected,
        "partial": rejected > 0,
        "backup_created": backup_dir.exists(),
        "backup": backup_dir.name if backup_dir.exists() else None,
    }


def _allowed(path: Path) -> bool:
    return path.name not in DENY_NAMES and path.suffix.lower() not in DENY_SUFFIXES


def _safe_source_file(path: Path, source_root: Path) -> bool:
    if not _allowed(path):
        return False
    try:
        resolved = path.resolve()
        root = source_root.resolve()
    except OSError:
        return False
    if resolved != root and root not in resolved.parents:
        return False
    try:
        path.relative_to(source_root)
    except ValueError:
        return False
    return path.is_file() and not path.is_symlink()
