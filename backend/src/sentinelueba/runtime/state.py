from __future__ import annotations

import threading
from dataclasses import dataclass
from pathlib import Path
from typing import Literal

RuntimeStateName = Literal["stopped", "starting", "ready", "degraded", "stopping", "failed"]


@dataclass
class RuntimeContext:
    mode: str = "development"
    state: RuntimeStateName = "stopped"
    port: int | None = None
    control_token: str | None = None
    process_identity: str | None = None
    shutdown_disabled: bool = False
    frontend_ready: bool = False
    database_ready: bool = False
    data_root_writable: bool = False
    service_collection_disabled: bool = False
    shutdown_requested: bool = False
    runtime_root: Path | None = None
    data_dir: Path | None = None
    database_path: Path | None = None
    model_dir: Path | None = None
    logs_dir: Path | None = None
    config_warning: str | None = None
    log_level: str = "INFO"

    @property
    def require_token(self) -> bool:
        return self.control_token is not None or self.mode in {"desktop", "service"}


_CONTEXT = RuntimeContext()
_LOCK = threading.Lock()


def get_runtime_context() -> RuntimeContext:
    with _LOCK:
        return RuntimeContext(**_CONTEXT.__dict__)


def update_runtime_context(**kwargs: object) -> RuntimeContext:
    with _LOCK:
        for key, value in kwargs.items():
            if hasattr(_CONTEXT, key):
                setattr(_CONTEXT, key, value)
        return RuntimeContext(**_CONTEXT.__dict__)
