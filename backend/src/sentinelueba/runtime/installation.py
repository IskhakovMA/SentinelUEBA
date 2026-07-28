from __future__ import annotations

import hashlib
import json
import os
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Literal

VerificationStatus = Literal[
    "verified",
    "unsigned_verified",
    "tampered",
    "incomplete",
    "unsupported_manifest",
]


def canonical_json(payload: object) -> bytes:
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode(
        "utf-8"
    )


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def sha256_bytes(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


@dataclass(frozen=True)
class VerificationResult:
    status: VerificationStatus
    signed: bool
    manifest_sha256: str | None
    checked_files: int
    errors: list[str]

    def safe_dict(self) -> dict[str, object]:
        return {
            "status": self.status,
            "signed": self.signed,
            "manifest_sha256": self.manifest_sha256,
            "checked_files": self.checked_files,
            "errors": self.errors,
        }


def create_frontend_asset_manifest(frontend_dir: Path) -> dict[str, object]:
    files: list[dict[str, object]] = []
    for path in sorted(frontend_dir.rglob("*")):
        if not path.is_file():
            continue
        rel = path.relative_to(frontend_dir).as_posix()
        if rel == "frontend-assets.json":
            continue
        files.append({"path": rel, "size": path.stat().st_size, "sha256": sha256_file(path)})
    return {
        "schema_version": 1,
        "files": files,
        "payload_sha256": sha256_bytes(canonical_json({"schema_version": 1, "files": files})),
    }


def write_frontend_asset_manifest(frontend_dir: Path) -> Path:
    manifest = create_frontend_asset_manifest(frontend_dir)
    target = frontend_dir / "frontend-assets.json"
    target.write_bytes(canonical_json(manifest))
    return target


def create_release_manifest(
    package_dir: Path,
    *,
    version: str,
    git_commit: str,
    build_timestamp_utc: str,
    signed: bool,
    frontend_manifest_sha256: str | None,
    dependency_inventory_sha256: str,
) -> dict[str, object]:
    files: list[dict[str, object]] = []
    for path in sorted(package_dir.rglob("*")):
        if not path.is_file():
            continue
        rel = path.relative_to(package_dir).as_posix()
        if rel == "release-manifest.json":
            continue
        files.append({"path": rel, "size": path.stat().st_size, "sha256": sha256_file(path)})
    payload: dict[str, object] = {
        "schema_version": 1,
        "application_version": version,
        "git_commit": git_commit,
        "build_timestamp_utc": build_timestamp_utc,
        "target_platform": "Windows",
        "target_architecture": "x64",
        "packaged_mode": "pyinstaller-one-folder",
        "signed": signed,
        "files": files,
        "frontend_manifest_sha256": frontend_manifest_sha256,
        "dependency_inventory_sha256": dependency_inventory_sha256,
    }
    payload["manifest_payload_sha256"] = sha256_bytes(canonical_json(payload))
    return payload


def verify_installation(package_dir: Path) -> VerificationResult:
    manifest_path = package_dir / "release-manifest.json"
    try:
        manifest_bytes = manifest_path.read_bytes()
        manifest = json.loads(manifest_bytes)
    except FileNotFoundError:
        return VerificationResult("incomplete", False, None, 0, ["release manifest is missing"])
    except json.JSONDecodeError:
        return VerificationResult(
            "unsupported_manifest",
            False,
            sha256_file(manifest_path),
            0,
            ["release manifest is not valid JSON"],
        )

    if manifest.get("schema_version") != 1 or not isinstance(manifest.get("files"), list):
        return VerificationResult(
            "unsupported_manifest",
            bool(manifest.get("signed")),
            sha256_file(manifest_path),
            0,
            ["unsupported release manifest schema"],
        )
    expected_payload_hash = manifest.get("manifest_payload_sha256")
    payload = dict(manifest)
    payload.pop("manifest_payload_sha256", None)
    actual_payload_hash = sha256_bytes(canonical_json(payload))
    if expected_payload_hash != actual_payload_hash:
        return VerificationResult(
            "tampered",
            bool(manifest.get("signed")),
            sha256_file(manifest_path),
            0,
            ["release manifest canonical hash mismatch"],
        )

    errors: list[str] = []
    checked = 0
    shipped = {str(item.get("path")) for item in manifest["files"] if isinstance(item, dict)}
    for item in manifest["files"]:
        if not isinstance(item, dict):
            errors.append("release manifest contains an invalid file record")
            continue
        rel = str(item.get("path"))
        target = package_dir / rel
        if not target.exists():
            errors.append(f"missing shipped file: {rel}")
            continue
        if not target.is_file():
            errors.append(f"invalid shipped file: {rel}")
            continue
        checked += 1
        if target.stat().st_size != int(item.get("size", -1)):
            errors.append(f"modified shipped file: {rel}")
            continue
        if sha256_file(target) != item.get("sha256"):
            errors.append(f"modified shipped file: {rel}")

    executable_suffixes = {".exe", ".dll", ".pyd"}
    for path in package_dir.rglob("*"):
        if path.is_file() and path.suffix.lower() in executable_suffixes:
            rel = path.relative_to(package_dir).as_posix()
            if rel not in shipped:
                errors.append(f"extra executable or library: {rel}")

    manifest_sha = sha256_file(manifest_path)
    signed = bool(manifest.get("signed"))
    if errors:
        return VerificationResult("tampered", signed, manifest_sha, checked, errors)
    status: VerificationStatus = "verified" if signed else "unsigned_verified"
    return VerificationResult(status, signed, manifest_sha, checked, [])


def current_executable_name() -> str:
    return Path(sys.executable).name if getattr(sys, "frozen", False) else Path(sys.argv[0]).name


def dependency_inventory_hash() -> str:
    payload = {
        "python": sys.version.split()[0],
        "executable": current_executable_name(),
        "path_lookup": os.getenv("PATH") is not None,
    }
    return sha256_bytes(canonical_json(payload))
