from __future__ import annotations

import socket
import threading
import time
import webbrowser
from contextlib import suppress
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import uvicorn

from sentinelueba import __version__
from sentinelueba.api.main import app as fastapi_app
from sentinelueba.collectors.manager import get_manager
from sentinelueba.config import Settings
from sentinelueba.detection.worker_manager import get_detection_worker_manager
from sentinelueba.runtime.build_info import is_packaged
from sentinelueba.runtime.control import (
    new_control_token,
    new_process_identity,
    status_now,
    write_private_text,
    write_status,
)
from sentinelueba.runtime.diagnostics import backup_before_migration, doctor
from sentinelueba.runtime.installation import verify_installation
from sentinelueba.runtime.instance import InstanceAlreadyRunningError, SingleInstanceLock
from sentinelueba.runtime.logging import configure_runtime_logging, log_event
from sentinelueba.runtime.paths import RuntimePaths, resolve_runtime_paths
from sentinelueba.runtime.state import get_runtime_context, update_runtime_context
from sentinelueba.storage.sqlite import SQLiteStorage


@dataclass(frozen=True)
class HostRunResult:
    state: str
    port: int | None
    url: str | None
    already_running: bool = False

    def safe_dict(self) -> dict[str, object]:
        return {
            "state": self.state,
            "port": self.port,
            "url": self.url,
            "already_running": self.already_running,
        }


def find_loopback_port(preferred_port: int | None = None) -> int:
    candidates = [preferred_port] if preferred_port is not None else []
    candidates.extend(range(8765, 8865))
    for port in candidates:
        if port is None:
            continue
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            if sock.connect_ex(("127.0.0.1", port)) != 0:
                return port
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


def frontend_dir(paths: RuntimePaths) -> Path:
    packaged = paths.package_dir / "frontend"
    if packaged.exists():
        return packaged
    return Path.cwd() / "frontend" / "dist"


def check_frontend_assets(paths: RuntimePaths) -> bool:
    root = frontend_dir(paths)
    if not is_packaged():
        return True
    return (root / "index.html").is_file() and (root / "frontend-assets.json").is_file()


def host_status(paths: RuntimePaths | None = None) -> dict[str, object]:
    resolved = paths or resolve_runtime_paths()
    context = get_runtime_context()
    status_path = resolved.runtime_dir / "status.json"
    payload: dict[str, object] = {
        "state": context.state,
        "mode": context.mode,
        "port": context.port,
        "version": __version__,
    }
    if status_path.exists():
        from sentinelueba.runtime.control import read_status

        persisted = read_status(status_path)
        if persisted is not None:
            payload.update(persisted.safe_dict())
            payload.pop("process_identity", None)
    return payload


def run_host(
    *,
    open_browser: bool = False,
    preferred_port: int | None = None,
    service: bool = False,
) -> HostRunResult:
    paths = resolve_runtime_paths(service=service)
    paths.ensure()
    token = new_control_token()
    configure_runtime_logging(
        paths.logs_dir,
        secrets=[token, str(paths.root), str(paths.package_dir)],
    )
    status_path = paths.runtime_dir / "status.json"
    token_path = paths.runtime_dir / "control.token"
    identity = new_process_identity()
    mode = "service" if service else paths.mode
    try:
        with SingleInstanceLock(paths.data_dir, paths.runtime_dir, status_path):
            update_runtime_context(
                mode=mode,
                state="starting",
                control_token=token,
                process_identity=identity,
                shutdown_disabled=service,
                service_collection_disabled=service,
            )
            write_private_text(token_path, token)
            port = find_loopback_port(preferred_port)
            write_status(
                status_path,
                status_now(
                    port=port,
                    mode=mode,
                    version=__version__,
                    state="starting",
                    identity=identity,
                ),
            )
            if is_packaged():
                verification = verify_installation(paths.package_dir)
                if verification.status not in {"verified", "unsigned_verified"}:
                    update_runtime_context(state="failed")
                    write_status(
                        status_path,
                        status_now(
                            port=port,
                            mode=mode,
                            version=__version__,
                            state="failed",
                            identity=identity,
                        ),
                    )
                    return HostRunResult("failed", port, None)
            backup_before_migration(paths)
            storage = SQLiteStorage(paths.database_path)
            storage.initialize()
            frontend_ready = check_frontend_assets(paths)
            update_runtime_context(
                port=port,
                state="ready" if frontend_ready else "degraded",
                frontend_ready=frontend_ready,
                database_ready=True,
                data_root_writable=True,
            )
            write_status(
                status_path,
                status_now(
                    port=port,
                    mode=mode,
                    version=__version__,
                    state="ready" if frontend_ready else "degraded",
                    identity=identity,
                ),
            )
            config = uvicorn.Config(
                fastapi_app,
                host="127.0.0.1",
                port=port,
                log_level="warning",
                access_log=False,
            )
            server = uvicorn.Server(config)
            thread = threading.Thread(target=server.run, daemon=True)
            thread.start()
            url = f"http://127.0.0.1:{port}/"
            if open_browser and not service:
                webbrowser.open(url)
            log_event("supervisor", "host_ready", "SentinelUEBA host is ready")
            while thread.is_alive():
                if get_runtime_context().shutdown_requested:
                    break
                time.sleep(0.2)
            update_runtime_context(state="stopping")
            server.should_exit = True
            thread.join(timeout=15)
            _shutdown_owned_managers(paths)
            return HostRunResult("stopped", port, url)
    except InstanceAlreadyRunningError as exc:
        status = exc.status
        existing_url = f"http://127.0.0.1:{status.port}/" if status is not None else None
        if open_browser and existing_url is not None:
            webbrowser.open(existing_url)
        return HostRunResult(
            "ready",
            status.port if status else None,
            existing_url,
            already_running=True,
        )
    finally:
        token_path.unlink(missing_ok=True)
        status_path.unlink(missing_ok=True)
        update_runtime_context(
            state="stopped",
            port=None,
            control_token=None,
            process_identity=None,
            shutdown_requested=False,
        )


def request_shutdown() -> None:
    update_runtime_context(state="stopping", shutdown_requested=True)


def _shutdown_owned_managers(paths: RuntimePaths) -> None:
    settings = Settings(
        data_dir=paths.data_dir,
        database_path=paths.database_path,
        model_dir=paths.model_dir,
    )
    with suppress(Exception):
        get_manager(settings).stop()
    get_detection_worker_manager().shutdown_process(
        database_path=paths.database_path,
        data_dir=paths.data_dir,
        model_dir=paths.model_dir,
    )


def doctor_report() -> dict[str, Any]:
    return doctor(resolve_runtime_paths())
