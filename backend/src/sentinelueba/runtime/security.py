from __future__ import annotations

import getpass
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Literal, Protocol

RuntimePrincipalMode = Literal["desktop", "service"]
BROAD_WINDOWS_PRINCIPALS = {"Authenticated Users", "Everyone", "Users"}


class RuntimeAclAdapter(Protocol):
    def protect_path(self, path: Path, *, mode: RuntimePrincipalMode, directory: bool) -> None: ...

    def verify_path(self, path: Path, *, mode: RuntimePrincipalMode) -> dict[str, object]: ...


@dataclass
class PosixAclAdapter:
    def protect_path(self, path: Path, *, mode: RuntimePrincipalMode, directory: bool) -> None:
        if directory:
            path.chmod(0o700)
        else:
            path.chmod(0o600)

    def verify_path(self, path: Path, *, mode: RuntimePrincipalMode) -> dict[str, object]:
        return {
            "path": path.name,
            "mode": mode,
            "protected": True,
            "windows_acl": False,
            "broad_users_read": False,
        }


class WindowsAclAdapter:
    def protect_path(self, path: Path, *, mode: RuntimePrincipalMode, directory: bool) -> None:
        try:
            import ntsecuritycon
            import win32security
        except Exception as exc:  # pragma: no cover - Windows dependency
            raise RuntimeError("pywin32 ACL modules are unavailable") from exc

        principals = ["SYSTEM", "Administrators"]
        principals.append("LOCAL SERVICE" if mode == "service" else _current_windows_user())
        dacl = win32security.ACL()
        rights = ntsecuritycon.FILE_ALL_ACCESS
        for principal in principals:
            sid, _domain, _sid_type = win32security.LookupAccountName(None, principal)
            dacl.AddAccessAllowedAceEx(
                win32security.ACL_REVISION,
                ntsecuritycon.OBJECT_INHERIT_ACE | ntsecuritycon.CONTAINER_INHERIT_ACE,
                rights,
                sid,
            )
        sd = win32security.GetFileSecurity(str(path), win32security.DACL_SECURITY_INFORMATION)
        sd.SetSecurityDescriptorDacl(1, dacl, 0)
        win32security.SetFileSecurity(str(path), win32security.DACL_SECURITY_INFORMATION, sd)

    def verify_path(self, path: Path, *, mode: RuntimePrincipalMode) -> dict[str, object]:
        try:
            import win32security
        except Exception as exc:  # pragma: no cover - Windows dependency
            raise RuntimeError("pywin32 ACL modules are unavailable") from exc

        sd = win32security.GetFileSecurity(str(path), win32security.DACL_SECURITY_INFORMATION)
        dacl = sd.GetSecurityDescriptorDacl()
        broad_users_read = False
        principals: set[str] = set()
        if dacl is not None:
            for index in range(dacl.GetAceCount()):
                ace = dacl.GetAce(index)
                sid = ace[2]
                name, _domain, _sid_type = win32security.LookupAccountSid(None, sid)
                principals.add(name)
                if name in BROAD_WINDOWS_PRINCIPALS:
                    broad_users_read = True
        expected = {"SYSTEM", "Administrators"}
        expected.add("LOCAL SERVICE" if mode == "service" else _current_windows_user())
        missing_expected = sorted(expected - principals)
        return {
            "path": path.name,
            "mode": mode,
            "protected": not broad_users_read and not missing_expected,
            "windows_acl": True,
            "broad_users_read": broad_users_read,
            "missing_expected_principals": missing_expected,
        }


def acl_adapter() -> RuntimeAclAdapter:
    return WindowsAclAdapter() if os.name == "nt" else PosixAclAdapter()


def _current_windows_user() -> str:
    try:
        import win32api

        return str(win32api.GetUserName())
    except Exception:
        return getpass.getuser()


def protect_runtime_secret(
    path: Path,
    *,
    mode: str,
    directory: bool = False,
    adapter: RuntimeAclAdapter | None = None,
) -> dict[str, object]:
    principal_mode: RuntimePrincipalMode = "service" if mode == "service" else "desktop"
    selected = adapter or acl_adapter()
    selected.protect_path(path, mode=principal_mode, directory=directory)
    return selected.verify_path(path, mode=principal_mode)
