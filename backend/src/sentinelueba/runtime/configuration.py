from __future__ import annotations

import json
import os
import shutil
import tempfile
from pathlib import Path
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator


class RuntimeConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

    config_schema_version: int = Field(default=1)
    runtime_mode: Literal["development", "desktop", "service"] = "development"
    preferred_port: int | None = Field(default=None, ge=1, le=65535)
    bind_host: Literal["127.0.0.1", "localhost"] = "127.0.0.1"
    open_browser: bool = False
    log_level: Literal["DEBUG", "INFO", "WARNING", "ERROR"] = "INFO"
    detection_worker_enabled: bool = False
    worker_dataset_kind: Literal["synthetic", "real"] = "synthetic"
    worker_interval_seconds: int = Field(default=60, ge=5, le=86400)
    worker_max_windows: int | None = Field(default=256, ge=1, le=100000)
    service_collection_disabled: bool = True
    retention_days_real_raw: int = Field(default=30, ge=1, le=3650)

    @field_validator("config_schema_version")
    @classmethod
    def _schema_v1(cls, value: int) -> int:
        if value != 1:
            raise ValueError("unsupported runtime config schema")
        return value


def default_config(mode: str = "development") -> RuntimeConfig:
    return RuntimeConfig(runtime_mode=mode)  # type: ignore[arg-type]


def load_config(path: Path, *, mode: str = "development") -> tuple[RuntimeConfig, str | None]:
    try:
        return RuntimeConfig.model_validate_json(path.read_text(encoding="utf-8")), None
    except FileNotFoundError:
        return default_config(mode), None
    except ValueError as exc:
        quarantine = path.with_suffix(path.suffix + ".invalid")
        shutil.copy2(path, quarantine)
        warning = f"invalid config quarantined: {quarantine.name}; {exc.__class__.__name__}"
        return default_config(mode), warning


def write_config(path: Path, config: RuntimeConfig) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists():
        shutil.copy2(path, path.with_suffix(path.suffix + ".bak"))
    fd, tmp_name = tempfile.mkstemp(prefix=path.name, suffix=".tmp", dir=path.parent)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(json.dumps(config.model_dump(), indent=2, sort_keys=True))
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(tmp_name, path)
    except Exception:
        Path(tmp_name).unlink(missing_ok=True)
        raise
