from __future__ import annotations

import json
import os
import sys
import time
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Protocol

from sentinelueba.runtime.build_info import package_root
from sentinelueba.runtime.installation import verify_installation
from sentinelueba.runtime.paths import resolve_runtime_paths
from sentinelueba.runtime.security import protect_runtime_secret
from sentinelueba.runtime.supervisor import run_host

SERVICE_ID = "SentinelUEBA"
SERVICE_DISPLAY_NAME = "SentinelUEBA Local Host"
SERVICE_ACCOUNT = r"NT AUTHORITY\LocalService"


class ServiceStartupFailed(RuntimeError):
    pass


class ServiceAdapter(Protocol):
    def is_installed(self) -> bool: ...

    def install(self, binary_path: Path) -> dict[str, object] | None: ...

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

    def install(self, binary_path: Path) -> dict[str, object]:
        if self.is_installed():
            self._validate_existing_service(binary_path)
            return self._install_result(binary_path, already_installed=True)

        quoted = f'"{binary_path}"'
        manager = self._win32service.OpenSCManager(
            None,
            None,
            self._win32service.SC_MANAGER_CREATE_SERVICE,
        )
        service: object | None = None
        recovery_error: Exception | None = None
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
            except Exception as exc:
                recovery_error = exc
            finally:
                self._win32service.CloseServiceHandle(service)
                service = None
        finally:
            if service is not None:
                self._win32service.CloseServiceHandle(service)
            self._win32service.CloseServiceHandle(manager)
        if recovery_error is not None:
            self._rollback_created_service(recovery_error)
        return self._install_result(binary_path, already_installed=False)

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

    def _configure_recovery(self) -> bool:
        import win32service

        handle = self._win32serviceutil.SmartOpenService(
            None,
            SERVICE_ID,
            win32service.SERVICE_CHANGE_CONFIG,
        )
        try:
            actions = service_recovery_actions(win32service)
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
            return True
        finally:
            win32service.CloseServiceHandle(handle)

    def _rollback_created_service(self, original_error: Exception) -> None:
        try:
            self._delete_service()
            self._wait_for_removed(timeout_seconds=10)
        except Exception as rollback_error:
            raise RuntimeError(
                "service installation failed and rollback was incomplete"
            ) from rollback_error
        raise RuntimeError(
            f"service recovery policy was not configured: {original_error.__class__.__name__}"
        ) from original_error

    def _delete_service(self) -> None:
        try:
            import win32service

            handle = self._win32serviceutil.SmartOpenService(
                None,
                SERVICE_ID,
                getattr(win32service, "DELETE", 0x00010000),
            )
            try:
                win32service.DeleteService(handle)
            finally:
                win32service.CloseServiceHandle(handle)
        except AttributeError:
            self._win32serviceutil.RemoveService(SERVICE_ID)

    def _wait_for_removed(self, *, timeout_seconds: float) -> None:
        deadline = time.monotonic() + timeout_seconds
        while time.monotonic() < deadline:
            if not self.is_installed():
                return
            time.sleep(0.2)
        raise RuntimeError("service rollback did not remove service")

    def _validate_existing_service(self, binary_path: Path) -> None:
        config = self._query_service_config()
        errors: list[str] = []
        if _normalize_service_binary(str(config["binary_path"])) != _normalize_service_binary(
            str(binary_path)
        ):
            errors.append("binary")
        if config["account"] != SERVICE_ACCOUNT:
            errors.append("account")
        if config["start_type"] != self._win32service.SERVICE_DEMAND_START:
            errors.append("start_type")
        if config["service_type"] != self._win32service.SERVICE_WIN32_OWN_PROCESS:
            errors.append("service_type")
        if not self._recovery_policy_matches():
            errors.append("recovery_policy")
        if errors:
            raise RuntimeError(
                "existing SentinelUEBA service configuration is not safe: "
                + ",".join(errors)
            )

    def _query_service_config(self) -> dict[str, object]:
        handle = self._win32serviceutil.SmartOpenService(
            None,
            SERVICE_ID,
            getattr(self._win32service, "SERVICE_QUERY_CONFIG", 1),
        )
        try:
            raw = self._win32service.QueryServiceConfig(handle)
        finally:
            self._win32service.CloseServiceHandle(handle)
        return {
            "service_type": raw[0],
            "start_type": raw[1],
            "binary_path": raw[3],
            "account": raw[7],
        }

    def _recovery_policy_matches(self) -> bool:
        handle = self._win32serviceutil.SmartOpenService(
            None,
            SERVICE_ID,
            getattr(self._win32service, "SERVICE_QUERY_CONFIG", 1),
        )
        try:
            raw = self._win32service.QueryServiceConfig2(
                handle,
                self._win32service.SERVICE_CONFIG_FAILURE_ACTIONS,
            )
        except Exception:
            return False
        finally:
            self._win32service.CloseServiceHandle(handle)
        actions = raw.get("Actions") if isinstance(raw, dict) else None
        return actions == service_recovery_actions(self._win32service)

    def _install_result(self, binary_path: Path, *, already_installed: bool) -> dict[str, object]:
        return {
            "service": SERVICE_ID,
            "status": self.status(),
            "binary": binary_path.name,
            "already_installed": already_installed,
            "recovery_configured": True,
            "account": SERVICE_ACCOUNT,
            "start_type": "manual",
        }


def service_adapter() -> ServiceAdapter:
    if os.name != "nt":
        return UnsupportedServiceAdapter()
    return PyWin32ServiceAdapter()


def _normalize_service_binary(value: str) -> str:
    stripped = value.strip().strip('"')
    return str(Path(stripped)).casefold()


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
        protect_runtime_secret(directory, mode="service", directory=True)
    selected = adapter or service_adapter()
    binary = service_binary_path()
    install_result = selected.install(binary)
    if isinstance(install_result, dict):
        return install_result
    return {
        "service": SERVICE_ID,
        "status": selected.status(),
        "binary": binary.name,
        "already_installed": False,
        "recovery_configured": True,
        "account": SERVICE_ACCOUNT,
        "start_type": "manual",
    }


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
            failed = False
            try:
                _run_service_host_or_raise(
                    log_error=servicemanager.LogErrorMsg,
                    report_failure=lambda: self.ReportServiceStatus(
                        win32service.SERVICE_STOPPED,
                        win32ExitCode=1,
                    ),
                )
            except ServiceStartupFailed:
                failed = True
                raise
            except Exception as exc:
                failed = True
                _write_service_failure_log(
                    "service_host_exception",
                    error_class=exc.__class__.__name__,
                )
                servicemanager.LogErrorMsg(
                    f"{SERVICE_DISPLAY_NAME} failed safely: {exc.__class__.__name__}"
                )
                raise
            finally:
                servicemanager.LogInfoMsg(f"{SERVICE_DISPLAY_NAME} stopped")
                if not failed:
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


def _write_service_failure_log(event: str, *, error_class: str) -> None:
    paths = resolve_runtime_paths(service=True)
    paths.logs_dir.mkdir(parents=True, exist_ok=True)
    protect_runtime_secret(paths.logs_dir, mode="service", directory=True)
    payload = {
        "timestamp_utc": datetime.now(UTC).replace(microsecond=0).isoformat().replace(
            "+00:00",
            "Z",
        ),
        "component": "service",
        "event": event,
        "error_class": error_class,
        "message": "SentinelUEBA Windows Service failed safely; inspect runtime status.",
    }
    path = paths.logs_dir / "service-failure.log"
    path.write_text(json.dumps(payload, sort_keys=True) + "\n", encoding="utf-8")
    protect_runtime_secret(path, mode="service")


def _run_service_host_or_raise(
    *,
    log_error: Callable[[str], object] | None = None,
    report_failure: Callable[[], object] | None = None,
) -> None:
    result = run_host(service=True, open_browser=False)
    if result.state != "failed":
        return
    _write_service_failure_log("service_host_failed", error_class="HostFailed")
    if log_error is not None:
        log_error("SentinelUEBA service host failed safely")
    if report_failure is not None:
        report_failure()
    raise ServiceStartupFailed("service host failed safely")


def service_recovery_actions(win32service_module: Any) -> list[tuple[Any, int]]:
    return [
        (win32service_module.SC_ACTION_RESTART, 60_000),
        (win32service_module.SC_ACTION_RESTART, 60_000),
        (win32service_module.SC_ACTION_RESTART, 60_000),
        (win32service_module.SC_ACTION_NONE, 0),
    ]


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
