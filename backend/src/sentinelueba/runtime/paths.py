from __future__ import annotations

import os
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Literal

from sentinelueba.runtime.build_info import is_packaged, package_root

RuntimeMode = Literal["development", "desktop", "service"]


@dataclass(frozen=True)
class RuntimePaths:
    mode: RuntimeMode
    root: Path
    config_dir: Path
    data_dir: Path
    database_path: Path
    model_dir: Path
    logs_dir: Path
    runtime_dir: Path
    backups_dir: Path
    package_dir: Path

    def ensure(self) -> None:
        for path in (
            self.config_dir,
            self.data_dir,
            self.database_path.parent,
            self.model_dir,
            self.logs_dir,
            self.runtime_dir,
            self.backups_dir,
        ):
            path.mkdir(parents=True, exist_ok=True)
            reject_escape(path, self.root)


def _env_path(name: str) -> Path | None:
    value = os.getenv(name)
    if value is None or not value.strip():
        return None
    return Path(value).expanduser()


def _windows_known_folder(name: str, fallback: Path) -> Path:
    value = os.getenv(name)
    if value:
        return Path(value)
    return fallback


def runtime_mode(service: bool = False) -> RuntimeMode:
    if service:
        return "service"
    override = os.getenv("SENTINELUEBA_RUNTIME_MODE")
    if override == "development":
        return "development"
    if override == "desktop":
        return "desktop"
    if override == "service":
        return "service"
    if is_packaged():
        return "desktop"
    return "development"


def default_root(mode: RuntimeMode) -> Path:
    if mode == "service":
        return _windows_known_folder(
            "PROGRAMDATA",
            Path(tempfile.gettempdir()) / "ProgramData",
        ) / "SentinelUEBA"
    if mode == "desktop":
        return _windows_known_folder(
            "LOCALAPPDATA",
            Path.home() / "AppData" / "Local",
        ) / "SentinelUEBA"
    return Path.cwd()


def resolve_runtime_paths(*, service: bool = False) -> RuntimePaths:
    mode = runtime_mode(service=service)
    root_override = None if mode == "service" else _env_path("SENTINELUEBA_RUNTIME_ROOT")
    root = (root_override or default_root(mode)).resolve()
    data_override = None if mode == "service" else _env_path("SENTINELUEBA_DATA_DIR")
    data_dir = (data_override or root / "data").resolve()
    database_override = None if mode == "service" else _env_path("SENTINELUEBA_DATABASE_PATH")
    database_path = (database_override or data_dir / "sentinelueba.sqlite3").resolve()
    model_override = None if mode == "service" else _env_path("SENTINELUEBA_MODEL_DIR")
    model_dir = (model_override or root / "models").resolve()
    paths = RuntimePaths(
        mode=mode,
        root=root,
        config_dir=(root / "config").resolve(),
        data_dir=data_dir,
        database_path=database_path,
        model_dir=model_dir,
        logs_dir=(root / "logs").resolve(),
        runtime_dir=(root / "runtime").resolve(),
        backups_dir=(root / "backups").resolve(),
        package_dir=package_root(),
    )
    if mode != "development":
        for candidate in (
            paths.config_dir,
            paths.data_dir,
            paths.database_path.parent,
            paths.model_dir,
        ):
            reject_escape(candidate, root)
    return paths


def reject_escape(path: Path, root: Path) -> None:
    resolved_root = root.resolve()
    resolved_path = path.resolve()
    if resolved_path != resolved_root and resolved_root not in resolved_path.parents:
        raise ValueError("runtime path escapes configured data root")


def safe_path_label(path: Path, root: Path) -> str:
    try:
        return str(path.resolve().relative_to(root.resolve())).replace("\\", "/")
    except ValueError:
        return "<outside-runtime-root>"
