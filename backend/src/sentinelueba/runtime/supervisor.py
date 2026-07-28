from __future__ import annotations

import socket
import sys
import threading
import time
import webbrowser
from contextlib import suppress
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import uvicorn

from sentinelueba import __version__
from sentinelueba.api.main import app as fastapi_app
from sentinelueba.collectors.manager import get_manager
from sentinelueba.config import Settings
from sentinelueba.detection.worker_manager import get_detection_worker_manager
from sentinelueba.runtime.build_info import is_packaged
from sentinelueba.runtime.configuration import load_config
from sentinelueba.runtime.control import (
    new_control_token,
    new_process_identity,
    status_now,
    write_private_text,
    write_status,
)
from sentinelueba.runtime.diagnostics import doctor, migrate_with_backup
from sentinelueba.runtime.installation import verify_installation
from sentinelueba.runtime.instance import InstanceAlreadyRunningError, SingleInstanceLock
from sentinelueba.runtime.logging import configure_runtime_logging, log_event
from sentinelueba.runtime.paths import RuntimePaths, resolve_runtime_paths
from sentinelueba.runtime.security import protect_runtime_secret
from sentinelueba.runtime.state import get_runtime_context, update_runtime_context


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
    if is_packaged():
        return paths.package_dir / "frontend"
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
    open_browser: bool | None = None,
    preferred_port: int | None = None,
    service: bool = False,
    windowed: bool = False,
    startup_timeout_seconds: float = 15.0,
) -> HostRunResult:
    paths = resolve_runtime_paths(service=service)
    paths.ensure()
    mode = "service" if service else paths.mode
    strict_acl = _strict_acl_required(mode)
    config, config_warning = load_config(paths.config_dir / "config.json", mode=mode)
    effective_port = preferred_port if preferred_port is not None else config.preferred_port
    effective_open_browser = bool(open_browser) if open_browser is not None else config.open_browser
    token = new_control_token()
    configure_runtime_logging(
        paths.logs_dir,
        level=config.log_level,
        secrets=[token, str(paths.root), str(paths.package_dir)],
    )
    try:
        _protect_runtime_surface(paths, mode=mode)
    except Exception:
        update_runtime_context(
            mode=mode,
            state="failed",
            runtime_root=paths.root,
            data_dir=paths.data_dir,
            database_path=paths.database_path,
            model_dir=paths.model_dir,
            logs_dir=paths.logs_dir,
            config_warning=config_warning,
            log_level=config.log_level,
        )
        return HostRunResult("failed", None, None)
    status_path = paths.runtime_dir / "status.json"
    token_path = paths.runtime_dir / "control.token"
    identity = new_process_identity()
    started_at = datetime.now(UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z")
    owns_instance = False
    owns_runtime_files = False
    server: uvicorn.Server | None = None
    thread: threading.Thread | None = None
    try:
        with SingleInstanceLock(paths.data_dir, paths.runtime_dir, status_path):
            owns_instance = True
            update_runtime_context(
                mode=mode,
                state="starting",
                control_token=token,
                process_identity=identity,
                shutdown_disabled=service,
                service_collection_disabled=service,
                runtime_root=paths.root,
                data_dir=paths.data_dir,
                database_path=paths.database_path,
                model_dir=paths.model_dir,
                logs_dir=paths.logs_dir,
                config_warning=config_warning,
                log_level=config.log_level,
            )
            write_private_text(token_path, token)
            if strict_acl:
                protect_runtime_secret(token_path, mode=mode)
            owns_runtime_files = True
            port = find_loopback_port(effective_port)
            write_status(
                status_path,
                status_now(
                    port=port,
                    mode=mode,
                    version=__version__,
                    state="starting",
                    identity=identity,
                    started_at=started_at,
                ),
            )
            if strict_acl:
                protect_runtime_secret(status_path, mode=mode)
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
                            started_at=started_at,
                        ),
                    )
                    return HostRunResult("failed", port, None)
            migration = migrate_with_backup(paths)
            if migration.get("status") == "failed":
                update_runtime_context(state="failed")
                write_status(
                    status_path,
                    status_now(
                        port=port,
                        mode=mode,
                        version=__version__,
                        state="failed",
                        identity=identity,
                        started_at=started_at,
                    ),
                )
                return HostRunResult("failed", port, None)
            frontend_ready = check_frontend_assets(paths)
            update_runtime_context(
                port=port,
                state="starting",
                frontend_ready=frontend_ready,
                database_ready=True,
                data_root_writable=True,
            )
            uvicorn_config = uvicorn.Config(
                fastapi_app,
                host=config.bind_host,
                port=port,
                log_config=(
                    None
                    if service or windowed or sys.stdout is None or sys.stderr is None
                    else uvicorn.config.LOGGING_CONFIG
                ),
                log_level=config.log_level.lower(),
                access_log=False,
            )
            server = uvicorn.Server(uvicorn_config)
            thread = threading.Thread(target=server.run, daemon=True)
            thread.start()
            if not _wait_for_server_start(server, thread, port, startup_timeout_seconds):
                update_runtime_context(state="failed")
                write_status(
                    status_path,
                    status_now(
                        port=port,
                        mode=mode,
                        version=__version__,
                        state="failed",
                        identity=identity,
                        started_at=started_at,
                    ),
                )
                server.should_exit = True
                thread.join(timeout=5)
                return HostRunResult("failed", port, None)
            final_state = "ready" if frontend_ready else "degraded"
            update_runtime_context(state=final_state)
            write_status(
                status_path,
                status_now(
                    port=port,
                    mode=mode,
                    version=__version__,
                    state=final_state,
                    identity=identity,
                    started_at=started_at,
                ),
            )
            url = f"http://127.0.0.1:{port}/"
            if effective_open_browser and not service:
                webbrowser.open(url)
            if config.detection_worker_enabled:
                with suppress(Exception):
                    get_detection_worker_manager().start(
                        database_path=paths.database_path,
                        data_dir=paths.data_dir,
                        model_dir=paths.model_dir,
                        dataset_kind=config.worker_dataset_kind,
                        interval_seconds=config.worker_interval_seconds,
                        max_windows=config.worker_max_windows,
                    )
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
        should_open_existing = open_browser is True or (
            open_browser is None and config.open_browser
        )
        if should_open_existing and existing_url is not None:
            webbrowser.open(existing_url)
        return HostRunResult(
            "ready",
            status.port if status else None,
            existing_url,
            already_running=True,
        )
    finally:
        if owns_instance and owns_runtime_files:
            if server is not None:
                server.should_exit = True
            if thread is not None and thread.is_alive():
                thread.join(timeout=5)
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


def _protect_runtime_surface(paths: RuntimePaths, *, mode: str) -> None:
    if not _strict_acl_required(mode):
        return
    for directory in (
        paths.root,
        paths.config_dir,
        paths.data_dir,
        paths.model_dir,
        paths.logs_dir,
        paths.runtime_dir,
        paths.backups_dir,
    ):
        protect_runtime_secret(directory, mode=mode, directory=True)


def _strict_acl_required(mode: str) -> bool:
    return mode == "service" or is_packaged()


def _wait_for_server_start(
    server: uvicorn.Server,
    thread: threading.Thread,
    port: int,
    timeout_seconds: float,
) -> bool:
    deadline = time.monotonic() + timeout_seconds
    while time.monotonic() < deadline:
        if getattr(server, "started", False):
            return _live_probe(port)
        if not thread.is_alive():
            return False
        if _live_probe(port):
            return True
        time.sleep(0.1)
    return False


def _live_probe(port: int) -> bool:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.settimeout(0.2)
        return sock.connect_ex(("127.0.0.1", port)) == 0


def doctor_report() -> dict[str, Any]:
    return doctor(resolve_runtime_paths())
