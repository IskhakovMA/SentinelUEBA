from __future__ import annotations

import getpass
import hashlib
import os
import platform
import secrets
from pathlib import Path


class IdentityProvider:
    def __init__(self, data_dir: Path, mode: str = "pseudonymous") -> None:
        self.data_dir = data_dir
        self.mode = mode
        self.secret_path = data_dir / "identity.secret"

    def user_host(self) -> tuple[str, str]:
        raw_user = getpass.getuser() or os.environ.get("USERNAME") or "unknown-user"
        raw_host = platform.node() or os.environ.get("COMPUTERNAME") or "unknown-host"
        if self.mode == "raw":
            return raw_user, raw_host
        salt = self._secret()
        return (
            f"user-{self._digest(raw_user, salt)}",
            f"host-{self._digest(raw_host, salt)}",
        )

    def _secret(self) -> str:
        self.data_dir.mkdir(parents=True, exist_ok=True)
        if not self.secret_path.exists():
            self.secret_path.write_text(secrets.token_hex(32), encoding="utf-8")
        return self.secret_path.read_text(encoding="utf-8").strip()

    @staticmethod
    def _digest(value: str, salt: str) -> str:
        digest = hashlib.sha256(f"{salt}:{value}".encode()).hexdigest()
        return digest[:16]

