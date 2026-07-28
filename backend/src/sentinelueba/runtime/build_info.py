from __future__ import annotations

import hashlib
import os
import platform
import sys
from dataclasses import asdict, dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Literal

from sentinelueba import __version__

BuildMode = Literal["development", "packaged"]


def is_packaged() -> bool:
    return bool(getattr(sys, "frozen", False)) or os.getenv("SENTINELUEBA_PACKAGED") == "1"


def package_root() -> Path:
    if bool(getattr(sys, "frozen", False)):
        return Path(sys.executable).resolve().parent
    override = os.getenv("SENTINELUEBA_PACKAGE_ROOT")
    if override:
        return Path(override).resolve()
    return Path.cwd().resolve()


def _safe_env(name: str, default: str) -> str:
    value = os.getenv(name)
    if value is None or not value.strip():
        return default
    return value.strip()


def _sha256(path: Path) -> str | None:
    if not path.exists() or not path.is_file():
        return None
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


@dataclass(frozen=True)
class BuildInfo:
    application_version: str
    git_commit: str
    build_timestamp_utc: str
    python_version: str
    platform: str
    mode: BuildMode
    frontend_build_hash: str | None
    release_manifest_sha256: str | None
    signed: bool

    def safe_dict(self) -> dict[str, object]:
        return asdict(self)


def get_build_info() -> BuildInfo:
    root = package_root()
    manifest_hash = _sha256(root / "release-manifest.json")
    frontend_manifest_hash = _sha256(root / "frontend" / "frontend-assets.json")
    build_timestamp = _safe_env(
        "SENTINELUEBA_BUILD_TIMESTAMP_UTC",
        datetime.now(UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z"),
    )
    return BuildInfo(
        application_version=__version__,
        git_commit=_safe_env("SENTINELUEBA_BUILD_COMMIT", "development"),
        build_timestamp_utc=build_timestamp,
        python_version=f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}",
        platform=f"{platform.system()}-{platform.machine()}",
        mode="packaged" if is_packaged() else "development",
        frontend_build_hash=frontend_manifest_hash,
        release_manifest_sha256=manifest_hash,
        signed=os.getenv("SENTINELUEBA_SIGNED", "0") == "1",
    )
