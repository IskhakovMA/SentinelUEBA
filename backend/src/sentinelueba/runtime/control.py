from __future__ import annotations

import json
import os
import secrets
from dataclasses import asdict, dataclass
from datetime import UTC, datetime
from pathlib import Path

CONTROL_HEADER = "X-SentinelUEBA-Control-Token"
CONTROL_TOKEN_BYTES = 32


@dataclass(frozen=True)
class RuntimeStatus:
    pid: int
    process_identity: str
    started_at: str
    port: int
    mode: str
    version: str
    state: str

    def safe_dict(self) -> dict[str, object]:
        return asdict(self)


def new_control_token() -> str:
    return secrets.token_urlsafe(CONTROL_TOKEN_BYTES)


def new_process_identity() -> str:
    return secrets.token_hex(16)


def write_private_text(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC
    fd = os.open(path, flags, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as handle:
        handle.write(text)
        handle.flush()
        os.fsync(handle.fileno())


def write_status(path: Path, status: RuntimeStatus) -> None:
    write_private_text(path, json.dumps(status.safe_dict(), sort_keys=True))


def read_status(path: Path) -> RuntimeStatus | None:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
        return RuntimeStatus(
            pid=int(payload["pid"]),
            process_identity=str(payload["process_identity"]),
            started_at=str(payload["started_at"]),
            port=int(payload["port"]),
            mode=str(payload["mode"]),
            version=str(payload["version"]),
            state=str(payload["state"]),
        )
    except (FileNotFoundError, KeyError, TypeError, ValueError, json.JSONDecodeError):
        return None


def status_now(*, port: int, mode: str, version: str, state: str, identity: str) -> RuntimeStatus:
    return RuntimeStatus(
        pid=os.getpid(),
        process_identity=identity,
        started_at=datetime.now(UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z"),
        port=port,
        mode=mode,
        version=version,
        state=state,
    )
