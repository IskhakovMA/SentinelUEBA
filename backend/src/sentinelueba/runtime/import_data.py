from __future__ import annotations

import shutil
from pathlib import Path

from sentinelueba.runtime.paths import RuntimePaths, reject_escape

DENY_NAMES = {"identity.secret", "control.token", "host.lock", "status.json"}
DENY_SUFFIXES = {".env", ".pfx", ".pem", ".key"}


def preview_import(source: Path) -> dict[str, object]:
    safe_source = source.expanduser().resolve()
    if not safe_source.exists() or not safe_source.is_dir():
        raise ValueError("source directory is not available")
    files = [
        path.relative_to(safe_source).as_posix()
        for path in sorted(safe_source.rglob("*"))
        if path.is_file() and _allowed(path)
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
    backup_dir = paths.backups_dir / "import-previous-data"
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
    for path in safe_source.rglob("*"):
        if not path.is_file() or not _allowed(path):
            continue
        rel = path.relative_to(safe_source)
        target = paths.data_dir / rel
        reject_escape(target.parent, paths.data_dir)
        target.parent.mkdir(parents=True, exist_ok=True)
        if target.exists():
            continue
        shutil.copy2(path, target)
        copied += 1
    return {"imported": copied, "backup_created": backup_dir.exists()}


def _allowed(path: Path) -> bool:
    return path.name not in DENY_NAMES and path.suffix.lower() not in DENY_SUFFIXES
