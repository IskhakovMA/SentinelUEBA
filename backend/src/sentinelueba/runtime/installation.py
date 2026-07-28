from __future__ import annotations

import hashlib
import importlib.metadata
import json
import os
import sys
from dataclasses import dataclass
from pathlib import Path, PurePosixPath, PureWindowsPath
from typing import Literal, Protocol

from sentinelueba import __version__

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


class AuthenticodeVerifier(Protocol):
    def verify(self, path: Path) -> bool: ...


class WindowsTrustAdapter:
    def verify(self, path: Path) -> bool:
        if os.name != "nt":
            return False
        try:
            import subprocess

            escaped = str(path).replace("'", "''")
            result = subprocess.run(
                [
                    "powershell",
                    "-NoProfile",
                    "-Command",
                    (
                        "$sig=Get-AuthenticodeSignature -LiteralPath "
                        f"'{escaped}'; "
                        "if ($sig.Status -eq 'Valid') { exit 0 } else { exit 1 }"
                    ),
                ],
                check=False,
                capture_output=True,
                text=True,
                timeout=20,
            )
            return result.returncode == 0
        except Exception:
            return False


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
        "executables": [
            "SentinelUEBA.exe",
            "SentinelUEBALauncher.exe",
            "SentinelUEBAService.exe",
        ],
    }
    payload["manifest_payload_sha256"] = sha256_bytes(canonical_json(payload))
    return payload


def verify_installation(
    package_dir: Path,
    *,
    authenticode: AuthenticodeVerifier | None = None,
) -> VerificationResult:
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
    root = package_dir.resolve()
    seen: set[str] = set()
    shipped: set[str] = set()
    for item in manifest["files"]:
        if not isinstance(item, dict):
            errors.append("release manifest contains an invalid file record")
            continue
        rel = str(item.get("path"))
        if not _valid_manifest_path(rel):
            errors.append(f"unsafe shipped file path: {rel}")
            continue
        if rel in seen:
            errors.append(f"duplicate shipped file path: {rel}")
            continue
        seen.add(rel)
        target = (package_dir / rel).resolve()
        if target != root and root not in target.parents:
            errors.append(f"shipped file escapes package root: {rel}")
            continue
        shipped.add(rel)
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

    if manifest.get("application_version") != __version__:
        errors.append("release manifest application version does not match runtime version")
    if manifest.get("target_platform") != "Windows":
        errors.append("release manifest target platform is invalid")
    if manifest.get("target_architecture") != "x64":
        errors.append("release manifest target architecture is invalid")
    if manifest.get("packaged_mode") != "pyinstaller-one-folder":
        errors.append("release manifest packaged mode is invalid")
    expected_exes = {"SentinelUEBA.exe", "SentinelUEBALauncher.exe", "SentinelUEBAService.exe"}
    manifest_exes = set(manifest.get("executables", []))
    if manifest_exes != expected_exes:
        errors.append("release manifest executable list is invalid")
    for executable in expected_exes:
        if executable not in shipped:
            errors.append(f"missing expected executable record: {executable}")

    frontend_manifest = package_dir / "frontend" / "frontend-assets.json"
    expected_frontend_hash = manifest.get("frontend_manifest_sha256")
    if expected_frontend_hash is not None:
        if not frontend_manifest.is_file():
            errors.append("frontend asset manifest is missing")
        elif sha256_file(frontend_manifest) != expected_frontend_hash:
            errors.append("frontend asset manifest hash mismatch")

    inventory = package_dir / "dependency-inventory.json"
    expected_inventory_hash = manifest.get("dependency_inventory_sha256")
    if not inventory.is_file():
        errors.append("dependency inventory is missing")
    elif sha256_file(inventory) != expected_inventory_hash:
        errors.append("dependency inventory hash mismatch")

    executable_suffixes = {".exe", ".dll", ".pyd"}
    for path in package_dir.rglob("*"):
        if path.is_file() and path.suffix.lower() in executable_suffixes:
            rel = path.relative_to(package_dir).as_posix()
            if rel not in shipped:
                errors.append(f"extra executable or library: {rel}")

    manifest_sha = sha256_file(manifest_path)
    signed = bool(manifest.get("signed"))
    if signed:
        verifier = authenticode or WindowsTrustAdapter()
        signed_targets = [
            path
            for path in package_dir.rglob("*")
            if path.is_file() and path.suffix.lower() in executable_suffixes
        ]
        invalid = [
            path.relative_to(package_dir).as_posix()
            for path in signed_targets
            if not verifier.verify(path)
        ]
        if invalid:
            errors.append(f"invalid Authenticode signature: {invalid[0]}")
    if errors:
        return VerificationResult("tampered", signed, manifest_sha, checked, errors)
    status: VerificationStatus = "verified" if signed else "unsigned_verified"
    return VerificationResult(status, signed, manifest_sha, checked, [])


def _valid_manifest_path(value: str) -> bool:
    if not value or "\\" in value:
        return False
    posix = PurePosixPath(value)
    windows = PureWindowsPath(value)
    return (
        not posix.is_absolute()
        and ".." not in posix.parts
        and not windows.is_absolute()
        and windows.drive == ""
        and not value.startswith("//")
    )


def current_executable_name() -> str:
    return Path(sys.executable).name if getattr(sys, "frozen", False) else Path(sys.argv[0]).name


def create_dependency_inventory() -> dict[str, object]:
    packages: list[dict[str, object]] = []
    for distribution in importlib.metadata.distributions():
        metadata = distribution.metadata
        name = metadata.get("Name")
        if not name:
            continue
        packages.append(
            {
                "name": name.casefold().replace("_", "-"),
                "version": distribution.version,
                "license": metadata.get("License") or metadata.get("Classifier", "unknown"),
            }
        )
    packages.sort(key=lambda item: (str(item["name"]), str(item["version"])))
    return {
        "schema_version": 1,
        "python": sys.version.split()[0],
        "packages": packages,
    }


def write_dependency_inventory(package_dir: Path) -> Path:
    target = package_dir / "dependency-inventory.json"
    target.write_bytes(canonical_json(create_dependency_inventory()))
    return target


def dependency_inventory_hash(package_dir: Path | None = None) -> str:
    if package_dir is not None:
        inventory = package_dir / "dependency-inventory.json"
        if inventory.is_file():
            return sha256_file(inventory)
    return sha256_bytes(canonical_json(create_dependency_inventory()))
