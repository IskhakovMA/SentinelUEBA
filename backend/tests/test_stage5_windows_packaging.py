from __future__ import annotations

import json
import os
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from sentinelueba import __version__
from sentinelueba.api.main import app
from sentinelueba.runtime.build_info import get_build_info
from sentinelueba.runtime.configuration import RuntimeConfig, load_config, write_config
from sentinelueba.runtime.control import CONTROL_HEADER, status_now, write_status
from sentinelueba.runtime.diagnostics import backup_before_migration
from sentinelueba.runtime.installation import (
    canonical_json,
    create_release_manifest,
    dependency_inventory_hash,
    sha256_file,
    verify_installation,
)
from sentinelueba.runtime.instance import InstanceAlreadyRunningError, SingleInstanceLock
from sentinelueba.runtime.paths import reject_escape, resolve_runtime_paths
from sentinelueba.runtime.service import UnsupportedServiceAdapter, install_service
from sentinelueba.runtime.state import update_runtime_context
from sentinelueba.runtime.supervisor import check_frontend_assets
from sentinelueba.storage.sqlite import DB_SCHEMA_VERSION, SQLiteStorage


def reset_runtime_context() -> None:
    update_runtime_context(
        mode="development",
        state="stopped",
        port=None,
        control_token=None,
        process_identity=None,
        shutdown_disabled=False,
        frontend_ready=False,
        database_ready=False,
        data_root_writable=False,
        service_collection_disabled=False,
        shutdown_requested=False,
    )


def test_stage5_version_and_build_identity_are_safe(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("SENTINELUEBA_BUILD_COMMIT", "abc123")
    monkeypatch.setenv("SENTINELUEBA_BUILD_TIMESTAMP_UTC", "2026-07-28T10:00:00Z")

    build = get_build_info().safe_dict()

    assert __version__ == "0.5.0"
    assert build["application_version"] == __version__
    assert build["git_commit"] == "abc123"
    assert build["build_timestamp_utc"] == "2026-07-28T10:00:00Z"
    blob = json.dumps(build)
    assert str(Path.home()) not in blob
    username = os.getenv("USER")
    if username:
        assert username not in blob


def test_stage5_runtime_paths_desktop_service_dev_and_escape(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    local_appdata = tmp_path / "Local App Data Unicode"
    program_data = tmp_path / "Program Data"
    monkeypatch.setenv("LOCALAPPDATA", str(local_appdata))
    monkeypatch.setenv("PROGRAMDATA", str(program_data))
    monkeypatch.setenv("SENTINELUEBA_PACKAGED", "1")
    monkeypatch.delenv("SENTINELUEBA_RUNTIME_MODE", raising=False)
    monkeypatch.delenv("SENTINELUEBA_RUNTIME_ROOT", raising=False)

    desktop = resolve_runtime_paths()
    assert desktop.mode == "desktop"
    assert desktop.root == (local_appdata / "SentinelUEBA").resolve()
    desktop.ensure()
    assert desktop.database_path.parent.exists()

    service = resolve_runtime_paths(service=True)
    assert service.mode == "service"
    assert service.root == (program_data / "SentinelUEBA").resolve()

    monkeypatch.setenv("SENTINELUEBA_RUNTIME_MODE", "development")
    monkeypatch.setenv("SENTINELUEBA_RUNTIME_ROOT", str(tmp_path / "dev root"))
    dev = resolve_runtime_paths()
    assert dev.mode == "development"
    assert "dev root" in str(dev.root)

    with pytest.raises(ValueError):
        reject_escape(tmp_path / "outside", desktop.root)


def test_stage5_installation_verification_detects_tamper(tmp_path: Path) -> None:
    package = tmp_path / "SentinelUEBA"
    package.mkdir()
    (package / "SentinelUEBA.exe").write_text("exe", encoding="utf-8")
    frontend = package / "frontend"
    frontend.mkdir()
    frontend_manifest = frontend / "frontend-assets.json"
    frontend_manifest.write_text("{}", encoding="utf-8")
    manifest = create_release_manifest(
        package,
        version="0.5.0",
        git_commit="abc123",
        build_timestamp_utc="2026-07-28T10:00:00Z",
        signed=False,
        frontend_manifest_sha256=sha256_file(frontend_manifest),
        dependency_inventory_sha256=dependency_inventory_hash(),
    )
    (package / "release-manifest.json").write_bytes(canonical_json(manifest))

    verified = verify_installation(package)
    assert verified.status == "unsigned_verified"
    assert verified.checked_files == 2

    (package / "SentinelUEBA.exe").write_text("tampered", encoding="utf-8")
    assert verify_installation(package).status == "tampered"


def test_stage5_control_token_host_origin_shutdown_and_service_collection(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    reset_runtime_context()
    monkeypatch.setenv("SENTINELUEBA_RUNTIME_MODE", "desktop")
    monkeypatch.setenv("SENTINELUEBA_RUNTIME_ROOT", str(tmp_path / "runtime"))
    update_runtime_context(
        mode="desktop",
        state="ready",
        port=8765,
        control_token="secret-token",
        frontend_ready=True,
        database_ready=True,
        data_root_writable=True,
    )
    client = TestClient(app)
    headers = {"host": "127.0.0.1:8765"}

    assert client.post("/api/demo/generate", headers=headers, json={"seed": 42}).status_code == 403
    assert (
        client.post(
            "/api/demo/generate",
            headers={**headers, CONTROL_HEADER: "wrong"},
            json={"seed": 42},
        ).status_code
        == 403
    )
    hostile = client.post(
        "/api/demo/generate",
        headers={**headers, CONTROL_HEADER: "secret-token", "origin": "http://evil.example"},
        json={"seed": 42},
    )
    assert hostile.status_code == 403

    ok = client.post(
        "/api/demo/generate",
        headers={**headers, CONTROL_HEADER: "secret-token", "origin": "http://127.0.0.1:8765"},
        json={"seed": 42},
    )
    assert ok.status_code == 200
    assert "secret-token" not in client.get("/api/runtime/status", headers=headers).text
    assert "secret-token" not in client.get("/api/runtime/build", headers=headers).text

    shutdown = client.post(
        "/api/runtime/shutdown",
        headers={**headers, CONTROL_HEADER: "secret-token"},
        json={"confirm": True},
    )
    assert shutdown.status_code == 200

    update_runtime_context(mode="service", shutdown_disabled=True)
    assert (
        client.post(
            "/api/runtime/shutdown",
            headers={**headers, CONTROL_HEADER: "secret-token"},
            json={"confirm": True},
        ).status_code
        == 409
    )
    assert (
        client.post(
            "/api/collection/start",
            headers={**headers, CONTROL_HEADER: "secret-token"},
            json={"interval_seconds": 5},
        ).status_code
        == 409
    )
    reset_runtime_context()


def test_stage5_single_instance_file_lock_and_stale_recovery(tmp_path: Path) -> None:
    runtime_dir = tmp_path / "runtime"
    status_path = runtime_dir / "status.json"
    with SingleInstanceLock(tmp_path / "data", runtime_dir, status_path):
        with (
            pytest.raises(InstanceAlreadyRunningError),
            SingleInstanceLock(tmp_path / "data", runtime_dir, status_path),
        ):
            pass
        with SingleInstanceLock(tmp_path / "other-data", tmp_path / "other-runtime", status_path):
            pass

    runtime_dir.mkdir(exist_ok=True)
    (runtime_dir / "host.lock").write_text("stale", encoding="utf-8")
    write_status(
        status_path,
        status_now(port=8765, mode="desktop", version="0.5.0", state="ready", identity="x"),
    )
    status = json.loads(status_path.read_text(encoding="utf-8"))
    status["pid"] = 99999999
    status_path.write_text(json.dumps(status), encoding="utf-8")
    with SingleInstanceLock(tmp_path / "data", runtime_dir, status_path):
        pass


def test_stage5_config_strict_validation_and_atomic_backup(tmp_path: Path) -> None:
    config_path = tmp_path / "config.json"
    config = RuntimeConfig(runtime_mode="desktop", preferred_port=8765)
    write_config(config_path, config)
    loaded, warning = load_config(config_path, mode="desktop")
    assert warning is None
    assert loaded.preferred_port == 8765

    write_config(config_path, RuntimeConfig(runtime_mode="desktop", preferred_port=8766))
    assert config_path.with_suffix(".json.bak").exists()
    config_path.write_text('{"config_schema_version":1,"unknown":true}', encoding="utf-8")
    recovered, warning = load_config(config_path, mode="desktop")
    assert recovered.runtime_mode == "desktop"
    assert warning is not None
    with pytest.raises(ValueError):
        RuntimeConfig.model_validate({"config_schema_version": 1, "bind_host": "0.0.0.0"})


def test_stage5_migration_backup_and_frontend_asset_check(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("SENTINELUEBA_RUNTIME_MODE", "desktop")
    monkeypatch.setenv("SENTINELUEBA_RUNTIME_ROOT", str(tmp_path / "runtime"))
    paths = resolve_runtime_paths()
    paths.ensure()
    storage = SQLiteStorage(paths.database_path)
    storage.initialize()
    assert backup_before_migration(paths)["created"] is False
    assert SQLiteStorage(paths.database_path).status()["schema_version"] == DB_SCHEMA_VERSION

    monkeypatch.setenv("SENTINELUEBA_PACKAGED", "1")
    monkeypatch.setenv("SENTINELUEBA_PACKAGE_ROOT", str(tmp_path / "package"))
    (tmp_path / "package").mkdir()
    assert check_frontend_assets(resolve_runtime_paths()) is False


def test_stage5_service_unsupported_platform_is_safe() -> None:
    if os.name == "nt":
        pytest.skip("unsupported platform path is non-Windows only")
    adapter = UnsupportedServiceAdapter()
    assert adapter.status() == "unsupported"
    with pytest.raises(RuntimeError):
        install_service(confirm=True, adapter=adapter)
