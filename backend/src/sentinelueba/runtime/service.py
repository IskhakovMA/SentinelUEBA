from __future__ import annotations

import os
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol

from sentinelueba.runtime.build_info import package_root
from sentinelueba.runtime.installation import verify_installation
from sentinelueba.runtime.supervisor import run_host

SERVICE_ID = "SentinelUEBA"
SERVICE_DISPLAY_NAME = "SentinelUEBA Local Host"


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
        self._win32serviceutil.InstallService(
            pythonClassString="sentinelueba.runtime.service.SentinelUEBAWindowsService",
            serviceName=SERVICE_ID,
            displayName=SERVICE_DISPLAY_NAME,
            startType=self._win32service.SERVICE_DEMAND_START,
            exeName=str(binary_path),
        )

    def uninstall(self) -> None:
        if self.is_installed():
            self._win32serviceutil.RemoveService(SERVICE_ID)

    def start(self) -> None:
        self._win32serviceutil.StartService(SERVICE_ID)

    def stop(self) -> None:
        self._win32serviceutil.StopService(SERVICE_ID)

    def status(self) -> str:
        if not self.is_installed():
            return "not_installed"
        state = self._win32serviceutil.QueryServiceStatus(SERVICE_ID)[1]
        return str(state)

    def logs(self) -> list[str]:
        return ["service logs are stored in ProgramData/SentinelUEBA/logs"]


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
    }


class SentinelUEBAWindowsService:  # pragma: no cover - imported only by pywin32 on Windows
    _svc_name_ = SERVICE_ID
    _svc_display_name_ = SERVICE_DISPLAY_NAME

    def SvcStop(self) -> None:
        from sentinelueba.runtime.supervisor import request_shutdown

        request_shutdown()

    def SvcDoRun(self) -> None:
        run_host(service=True)
