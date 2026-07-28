from __future__ import annotations

import os
import sys
import time
import traceback
from contextlib import suppress
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol

from sentinelueba.runtime.build_info import package_root
from sentinelueba.runtime.installation import verify_installation
from sentinelueba.runtime.paths import resolve_runtime_paths
from sentinelueba.runtime.security import protect_runtime_secret
from sentinelueba.runtime.supervisor import run_host

SERVICE_ID = "SentinelUEBA"
SERVICE_DISPLAY_NAME = "SentinelUEBA Local Host"
SERVICE_ACCOUNT = r"NT AUTHORITY\LocalService"


class ServiceAdapter(Protocol):
    def is_installed(self) -> bool: ...

    def install(self, binary_path: Path) -> None: ...

    def uninstall(self) -> None: ...

    def start(self) -> None: ...

    def stop(self) -> None: ...

    def status(self) -> str: ...

    def logs(self) -> list[str]: ...


@dataclass
class UnsupportedServiceAdapter:
    reason: str = "Windows Service control is supported only on Windows"

    def is_installed(self) -> bool:
        return False

    def install(self, binary_path: Path) -> None:
        raise RuntimeError(self.reason)

    def uninstall(self) -> None:
        raise RuntimeError(self.reason)

    def start(self) -> None:
        raise RuntimeError(self.reason)

    def stop(self) -> None:
        raise RuntimeError(self.reason)

    def status(self) -> str:
        return "unsupported"

    def logs(self) -> list[str]:
        return []


class PyWin32ServiceAdapter:
    def __init__(self) -> None:
        import win32service
        import win32serviceutil

        self._win32service = win32service
        self._win32serviceutil = win32serviceutil

    def is_installed(self) -> bool:
        try:
            self._win32serviceutil.QueryServiceStatus(SERVICE_ID)
            return True
        except Exception:
            return False

    def install(self, binary_path: Path) -> None:
        quoted = f'"{binary_path}"'
        manager = self._win32service.OpenSCManager(
            None,
            None,
            self._win32service.SC_MANAGER_CREATE_SERVICE,
        )
        try:
            service = self._win32service.CreateService(
                manager,
                SERVICE_ID,
                SERVICE_DISPLAY_NAME,
                self._win32service.SERVICE_ALL_ACCESS,
                self._win32service.SERVICE_WIN32_OWN_PROCESS,
                self._win32service.SERVICE_DEMAND_START,
                self._win32service.SERVICE_ERROR_NORMAL,
                quoted,
                None,
                0,
                None,
                SERVICE_ACCOUNT,
                None,
            )
            try:
                self._configure_recovery()
            finally:
                self._win32service.CloseServiceHandle(service)
        finally:
            self._win32service.CloseServiceHandle(manager)

    def uninstall(self) -> None:
        if self.is_installed():
            self._win32serviceutil.RemoveService(SERVICE_ID)

    def start(self) -> None:
        self._win32serviceutil.StartService(SERVICE_ID)

    def stop(self) -> None:
        try:
            self._win32serviceutil.StopService(SERVICE_ID)
        except Exception as exc:
            if "1062" not in str(exc):
                raise
            return
        wait_for_service_status(self, stopped=True, timeout_seconds=30)

    def status(self) -> str:
        if not self.is_installed():
            return "not_installed"
        state = self._win32serviceutil.QueryServiceStatus(SERVICE_ID)[1]
        return str(state)

    def logs(self) -> list[str]:
        return ["service logs are stored in ProgramData/SentinelUEBA/logs"]

    def _configure_recovery(self) -> None:
        try:
            import win32service

            handle = self._win32serviceutil.SmartOpenService(
                None,
                SERVICE_ID,
                win32service.SERVICE_CHANGE_CONFIG,
            )
            try:
                actions = [
                    (win32service.SC_ACTION_RESTART, 60_000),
                    (win32service.SC_ACTION_RESTART, 60_000),
                    (win32service.SC_ACTION_RESTART, 60_000),
                    (win32service.SC_ACTION_NONE, 0),
                ]
                win32service.ChangeServiceConfig2(
                    handle,
                    win32service.SERVICE_CONFIG_FAILURE_ACTIONS,
                    {
                        "ResetPeriod": 86400,
                        "RebootMsg": None,
                        "Command": None,
                        "Actions": actions,
                    },
                )
            finally:
                win32service.CloseServiceHandle(handle)
        except Exception:
            return


def service_adapter() -> ServiceAdapter:
    if os.name != "nt":
        return UnsupportedServiceAdapter()
    return PyWin32ServiceAdapter()


def is_admin() -> bool:
    if os.name != "nt":
        return False
    try:
        import ctypes

        return bool(ctypes.windll.shell32.IsUserAnAdmin())  # type: ignore[attr-defined]
    except Exception:
        return False


def service_binary_path() -> Path:
    root = package_root()
    candidate = root / "SentinelUEBAService.exe"
    if candidate.exists():
        return candidate
    return Path(sys.executable)


def install_service(*, confirm: bool, adapter: ServiceAdapter | None = None) -> dict[str, object]:
    if os.name != "nt":
        raise RuntimeError("Windows Service control is supported only on Windows")
    if not confirm:
        raise ValueError("service install requires --confirm")
    if not is_admin():
        raise PermissionError("administrator privileges are required")
    verification = verify_installation(package_root())
    if verification.status not in {"verified", "unsigned_verified"}:
        raise RuntimeError("installation verification failed")
    paths = resolve_runtime_paths(service=True)
    paths.ensure()
    for directory in (
        paths.root,
        paths.config_dir,
        paths.data_dir,
        paths.model_dir,
        paths.logs_dir,
        paths.runtime_dir,
        paths.backups_dir,
    ):
        with suppress(Exception):
            protect_runtime_secret(directory, mode="service", directory=True)
    selected = adapter or service_adapter()
    binary = service_binary_path()
    if not selected.is_installed():
        selected.install(binary)
    return {"service": SERVICE_ID, "status": selected.status(), "binary": binary.name}


def uninstall_service(*, confirm: bool, adapter: ServiceAdapter | None = None) -> dict[str, object]:
    if os.name != "nt":
        raise RuntimeError("Windows Service control is supported only on Windows")
    if not confirm:
        raise ValueError("service uninstall requires --confirm")
    selected = adapter or service_adapter()
    selected.uninstall()
    return {"service": SERVICE_ID, "status": "not_installed"}


def run_service_debug_smoke() -> dict[str, object]:
    return {
        "service": SERVICE_ID,
        "display_name": SERVICE_DISPLAY_NAME,
        "mode": "debug-smoke",
        "status": "ok",
        "binary": service_binary_path().name,
        "account": SERVICE_ACCOUNT,
    }


if os.name == "nt":  # pragma: no cover - imported only by pywin32 on Windows
    import servicemanager
    import win32event
    import win32service
    import win32serviceutil

    class SentinelUEBAWindowsService(win32serviceutil.ServiceFramework):  # type: ignore[misc]
        _svc_name_ = SERVICE_ID
        _svc_display_name_ = SERVICE_DISPLAY_NAME

        def __init__(self, args: list[str]) -> None:
            win32serviceutil.ServiceFramework.__init__(self, args)
            self.stop_event = win32event.CreateEvent(None, 0, 0, None)

        def SvcStop(self) -> None:
            self.ReportServiceStatus(win32service.SERVICE_STOP_PENDING)
            from sentinelueba.runtime.supervisor import request_shutdown

            request_shutdown()
            win32event.SetEvent(self.stop_event)

        def SvcDoRun(self) -> None:
            servicemanager.LogInfoMsg(f"{SERVICE_DISPLAY_NAME} starting")
            self.ReportServiceStatus(win32service.SERVICE_START_PENDING)
            self.ReportServiceStatus(win32service.SERVICE_RUNNING)
            try:
                result = run_host(service=True, open_browser=False)
                if result.state == "failed":
                    message = "SentinelUEBA service host returned failed"
                    _write_service_failure_log(message)
                    servicemanager.LogErrorMsg(message)
            except Exception as exc:
                details = traceback.format_exc()
                _write_service_failure_log(details)
                servicemanager.LogErrorMsg(f"{SERVICE_DISPLAY_NAME} failed: {exc!r}")
                raise
            finally:
                servicemanager.LogInfoMsg(f"{SERVICE_DISPLAY_NAME} stopped")
                self.ReportServiceStatus(win32service.SERVICE_STOPPED)

else:

    class SentinelUEBAWindowsService:  # type: ignore[no-redef]
        _svc_name_ = SERVICE_ID
        _svc_display_name_ = SERVICE_DISPLAY_NAME


def dispatch_service() -> None:
    if os.name != "nt":
        run_host(service=True)
        return
    import servicemanager

    servicemanager.Initialize(SERVICE_ID, SERVICE_DISPLAY_NAME)
    servicemanager.PrepareToHostSingle(SentinelUEBAWindowsService)
    servicemanager.StartServiceCtrlDispatcher()


def handle_service_command_line() -> None:
    if os.name != "nt":
        run_host(service=True)
        return
    import win32serviceutil

    win32serviceutil.HandleCommandLine(SentinelUEBAWindowsService)


def _write_service_failure_log(message: str) -> None:
    with suppress(Exception):
        paths = resolve_runtime_paths(service=True)
        paths.logs_dir.mkdir(parents=True, exist_ok=True)
        (paths.logs_dir / "service-failure.log").write_text(message, encoding="utf-8")


def wait_for_service_status(
    adapter: ServiceAdapter,
    *,
    stopped: bool,
    timeout_seconds: float = 30.0,
) -> str:
    deadline = time.monotonic() + timeout_seconds
    latest = adapter.status()
    while time.monotonic() < deadline:
        latest = adapter.status()
        if stopped and latest in {"not_installed", "1", "stopped"}:
            return latest
        if not stopped and latest not in {"not_installed", "1", "stopped"}:
            return latest
        time.sleep(0.5)
    return latest
