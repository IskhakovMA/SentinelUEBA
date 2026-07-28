from __future__ import annotations

import importlib.util
import json
import os
import sqlite3
import sys
import time
import types
from contextlib import suppress
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from threading import Thread
from typing import Any

import pytest
from fastapi.testclient import TestClient
from typer.testing import CliRunner

from sentinelueba import __version__
from sentinelueba.api.main import app
from sentinelueba.cli import app as cli_app
from sentinelueba.runtime.build_info import get_build_info
from sentinelueba.runtime.configuration import RuntimeConfig, load_config, write_config
from sentinelueba.runtime.control import CONTROL_HEADER, status_now, write_status
from sentinelueba.runtime.diagnostics import (
    backup_before_migration,
    doctor,
    inspect_schema,
    migrate_with_backup,
)
from sentinelueba.runtime.installation import (
    canonical_json,
    create_release_manifest,
    sha256_bytes,
    sha256_file,
    verify_installation,
    write_dependency_inventory,
)
from sentinelueba.runtime.instance import InstanceAlreadyRunningError, SingleInstanceLock
from sentinelueba.runtime.paths import reject_escape, resolve_runtime_paths
from sentinelueba.runtime.security import RuntimeAclVerificationError, protect_runtime_secret
from sentinelueba.runtime.service import (
    SERVICE_ACCOUNT,
    SERVICE_DISPLAY_NAME,
    SERVICE_ID,
    PyWin32ServiceAdapter,
    ServiceStartupFailed,
    UnsupportedServiceAdapter,
    _run_service_host_or_raise,
    install_service,
    service_recovery_actions,
)
from sentinelueba.runtime.state import update_runtime_context
from sentinelueba.runtime.supervisor import (
    HostRunResult,
    _wait_for_server_start,
    check_frontend_assets,
    frontend_dir,
    run_host,
)
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
        runtime_root=None,
        data_dir=None,
        database_path=None,
        model_dir=None,
        logs_dir=None,
        config_warning=None,
        log_level="INFO",
    )


def create_package_fixture(
    package: Path,
    *,
    signed: bool = False,
    version: str = "0.5.0",
) -> dict[str, object]:
    package.mkdir(parents=True, exist_ok=True)
    for name in ("SentinelUEBA.exe", "SentinelUEBALauncher.exe", "SentinelUEBAService.exe"):
        (package / name).write_text(name, encoding="utf-8")
    frontend = package / "frontend"
    frontend.mkdir()
    (frontend / "index.html").write_text("<div>SentinelUEBA</div>", encoding="utf-8")
    frontend_manifest = frontend / "frontend-assets.json"
    frontend_manifest.write_text("{}", encoding="utf-8")
    inventory = write_dependency_inventory(package)
    manifest = create_release_manifest(
        package,
        version=version,
        git_commit="abc123",
        build_timestamp_utc="2026-07-28T10:00:00Z",
        signed=signed,
        frontend_manifest_sha256=sha256_file(frontend_manifest),
        dependency_inventory_sha256=sha256_file(inventory),
    )
    (package / "release-manifest.json").write_bytes(canonical_json(manifest))
    return manifest


def execute_sql(database: Path, *statements: str | tuple[str, tuple[object, ...]]) -> None:
    conn = sqlite3.connect(database)
    try:
        for statement in statements:
            if isinstance(statement, tuple):
                conn.execute(statement[0], statement[1])
            else:
                conn.execute(statement)
        conn.commit()
    finally:
        conn.close()


def load_launcher_module() -> Any:
    launcher_path = (
        Path(__file__).resolve().parents[2] / "packaging" / "windows" / "launcher_entry.py"
    )
    spec = importlib.util.spec_from_file_location("sentinelueba_launcher_entry", launcher_path)
    assert spec is not None and spec.loader is not None
    launcher = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(launcher)
    return launcher


class FakeUvicornServer:
    def __init__(self, *, started: bool) -> None:
        self.started = started


class FakeServerThread:
    def __init__(self, *, alive: bool) -> None:
        self._alive = alive

    def is_alive(self) -> bool:
        return self._alive


def start_health_server(
    *,
    body: bytes,
    content_type: str = "application/json",
    status_code: int = 200,
) -> tuple[ThreadingHTTPServer, int, Thread]:
    class Handler(BaseHTTPRequestHandler):
        def do_GET(self) -> None:
            self.send_response(status_code)
            self.send_header("Content-Type", content_type)
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, _format: str, *_args: object) -> None:
            return None

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server, int(server.server_address[1]), thread


def install_fake_scm_modules(
    monkeypatch: pytest.MonkeyPatch,
    *,
    installed: bool = False,
    binary_path: str = "",
    account: str = SERVICE_ACCOUNT,
    start_type: int = 4,
    service_type: int = 3,
    recovery_actions: list[tuple[int, int]] | None = None,
    fail_recovery: bool = False,
    fail_delete: bool = False,
) -> dict[str, object]:
    state: dict[str, object] = {
        "installed": installed,
        "binary_path": binary_path,
        "account": account,
        "start_type": start_type,
        "service_type": service_type,
        "recovery_actions": recovery_actions,
        "fail_recovery": fail_recovery,
        "fail_delete": fail_delete,
        "deleted": False,
        "created": 0,
    }
    calls: list[tuple[str, object]] = []
    state["calls"] = calls

    def query_status(_service_id: str) -> tuple[None, int]:
        if state["installed"] is not True:
            raise RuntimeError("missing")
        return (None, 4)

    def create_service(*args: object) -> str:
        state["installed"] = True
        state["created"] = int(state["created"]) + 1
        state["service_type"] = args[4]
        state["start_type"] = args[5]
        state["binary_path"] = str(args[7])
        state["account"] = str(args[11])
        calls.append(("create_service", args))
        return "service"

    def change_service_config2(_handle: object, _kind: object, config: dict[str, object]) -> None:
        calls.append(("recovery", config))
        if state["fail_recovery"] is True:
            raise RuntimeError("recovery failed")
        state["recovery_actions"] = config["Actions"]

    def delete_service(_handle: object) -> None:
        calls.append(("delete_service", None))
        if state["fail_delete"] is True:
            raise RuntimeError("delete failed")
        state["installed"] = False
        state["deleted"] = True
        state["recovery_actions"] = None

    def query_service_config(
        _handle: object,
    ) -> tuple[object, int, None, str, None, None, None, str, str]:
        return (
            state["service_type"],
            int(state["start_type"]),
            None,
            str(state["binary_path"]),
            None,
            None,
            None,
            str(state["account"]),
            SERVICE_DISPLAY_NAME,
        )

    def query_service_config2(_handle: object, _kind: object) -> dict[str, object]:
        actions = state["recovery_actions"]
        if actions is None:
            return {}
        return {"Actions": actions}

    fake_win32service = types.SimpleNamespace(
        SC_MANAGER_CREATE_SERVICE=1,
        SERVICE_QUERY_CONFIG=1,
        DELETE=0x00010000,
        SERVICE_ALL_ACCESS=2,
        SERVICE_WIN32_OWN_PROCESS=3,
        SERVICE_DEMAND_START=4,
        SERVICE_ERROR_NORMAL=5,
        SERVICE_CHANGE_CONFIG=6,
        SERVICE_CONFIG_FAILURE_ACTIONS=7,
        SC_ACTION_RESTART=8,
        SC_ACTION_NONE=9,
        OpenSCManager=lambda *args: calls.append(("open_manager", args)) or "manager",
        CreateService=create_service,
        CloseServiceHandle=lambda handle: calls.append(("close", handle)),
        SmartOpenService=lambda *args: calls.append(("smart_open", args)) or "service-handle",
        ChangeServiceConfig2=change_service_config2,
        QueryServiceConfig=query_service_config,
        QueryServiceConfig2=query_service_config2,
        DeleteService=delete_service,
    )
    fake_service_util = types.SimpleNamespace(
        QueryServiceStatus=query_status,
        SmartOpenService=fake_win32service.SmartOpenService,
        StartService=lambda *_args: None,
        StopService=lambda *_args: None,
        RemoveService=lambda _service_id: delete_service("remove-service"),
    )
    monkeypatch.setitem(sys.modules, "win32service", fake_win32service)
    monkeypatch.setitem(sys.modules, "win32serviceutil", fake_service_util)
    return state


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


def test_stage5_packaged_build_identity_comes_from_manifest(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    package = tmp_path / "SentinelUEBA"
    manifest = create_package_fixture(package)
    monkeypatch.setenv("SENTINELUEBA_PACKAGED", "1")
    monkeypatch.setenv("SENTINELUEBA_PACKAGE_ROOT", str(package))
    monkeypatch.setenv("SENTINELUEBA_BUILD_COMMIT", "development")
    monkeypatch.setenv("SENTINELUEBA_BUILD_TIMESTAMP_UTC", "now")
    monkeypatch.setenv("SENTINELUEBA_SIGNED", "1")

    first = get_build_info().safe_dict()
    second = get_build_info().safe_dict()

    assert first["application_version"] == __version__
    assert first["git_commit"] == manifest["git_commit"]
    assert first["git_commit"] != "development"
    assert first["build_timestamp_utc"] == "2026-07-28T10:00:00Z"
    assert second["build_timestamp_utc"] == first["build_timestamp_utc"]
    assert first["signed"] is False


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

    monkeypatch.setenv("SENTINELUEBA_RUNTIME_ROOT", str(tmp_path / "desktop override"))
    service_isolated = resolve_runtime_paths(service=True)
    assert service_isolated.root == (program_data / "SentinelUEBA").resolve()
    assert local_appdata not in service_isolated.database_path.parents

    monkeypatch.setenv("SENTINELUEBA_RUNTIME_MODE", "development")
    monkeypatch.setenv("SENTINELUEBA_RUNTIME_ROOT", str(tmp_path / "dev root"))
    dev = resolve_runtime_paths()
    assert dev.mode == "development"
    assert "dev root" in str(dev.root)

    with pytest.raises(ValueError):
        reject_escape(tmp_path / "outside", desktop.root)


def test_stage5_installation_verification_detects_tamper_and_path_attacks(tmp_path: Path) -> None:
    package = tmp_path / "SentinelUEBA"
    manifest = create_package_fixture(package)

    verified = verify_installation(package)
    assert verified.status == "unsigned_verified"
    assert verified.checked_files >= 5

    (package / "SentinelUEBA.exe").write_text("tampered", encoding="utf-8")
    assert verify_installation(package).status == "tampered"

    (package / "SentinelUEBA.exe").write_text("SentinelUEBA.exe", encoding="utf-8")
    bad = dict(manifest)
    bad["files"] = [*manifest["files"], {"path": "../escape.txt", "size": 0, "sha256": "x"}]
    bad.pop("manifest_payload_sha256", None)
    bad["manifest_payload_sha256"] = sha256_file(package / "SentinelUEBA.exe")
    (package / "release-manifest.json").write_bytes(canonical_json(bad))
    assert "canonical hash mismatch" in verify_installation(package).errors[0]


def test_stage5_manifest_rejects_duplicate_absolute_and_fake_signed(
    tmp_path: Path,
) -> None:
    package = tmp_path / "SentinelUEBA"
    manifest = create_package_fixture(package, signed=True)
    files = list(manifest["files"])
    files.append(dict(files[0]))
    files.append({"path": "C:/escape.exe", "size": 1, "sha256": "x"})
    payload = dict(manifest, files=files)
    payload.pop("manifest_payload_sha256", None)
    payload["manifest_payload_sha256"] = sha256_bytes(canonical_json(payload))
    (package / "release-manifest.json").write_bytes(canonical_json(payload))

    class RejectingTrust:
        def verify(self, path: Path) -> bool:
            return False

    result = verify_installation(package, authenticode=RejectingTrust())
    assert result.status == "tampered"
    assert any("duplicate" in error for error in result.errors)
    assert any("unsafe" in error for error in result.errors)
    assert any("Authenticode" in error for error in result.errors)


def test_stage5_manifest_rejects_consistency_and_inventory_mismatches(tmp_path: Path) -> None:
    package = tmp_path / "wrong-version"
    manifest = create_package_fixture(package)

    changed = dict(manifest)
    changed["application_version"] = "9.9.9"
    changed.pop("manifest_payload_sha256", None)
    changed["manifest_payload_sha256"] = sha256_bytes(canonical_json(changed))
    (package / "release-manifest.json").write_bytes(canonical_json(changed))
    assert "application version" in " ".join(verify_installation(package).errors)

    package = tmp_path / "wrong-frontend-manifest"
    create_package_fixture(package)
    (package / "frontend" / "frontend-assets.json").write_text("changed", encoding="utf-8")
    assert "frontend asset manifest hash mismatch" in verify_installation(package).errors

    package = tmp_path / "wrong-inventory"
    create_package_fixture(package)
    (package / "dependency-inventory.json").write_text("changed", encoding="utf-8")
    assert "dependency inventory hash mismatch" in verify_installation(package).errors

    package = tmp_path / "modified-frontend"
    create_package_fixture(package)
    (package / "frontend" / "index.html").write_text("changed", encoding="utf-8")
    result = verify_installation(package)
    assert any("modified shipped file: frontend/index.html" in error for error in result.errors)

    package = tmp_path / "extra-exe"
    create_package_fixture(package)
    (package / "extra.exe").write_text("extra", encoding="utf-8")
    assert "extra executable or library: extra.exe" in verify_installation(package).errors


def test_stage5_manifest_rejects_symlink_escape(tmp_path: Path) -> None:
    package = tmp_path / "SentinelUEBA"
    create_package_fixture(package)
    outside = tmp_path / "outside.txt"
    outside.write_text("outside", encoding="utf-8")
    link = package / "linked.txt"
    with suppress(OSError):
        link.symlink_to(outside)
    if not link.exists():
        pytest.skip("symlink creation is unavailable")
    inventory = package / "dependency-inventory.json"
    frontend_manifest = package / "frontend" / "frontend-assets.json"
    manifest = create_release_manifest(
        package,
        version=__version__,
        git_commit="abc123",
        build_timestamp_utc="2026-07-28T10:00:00Z",
        signed=False,
        frontend_manifest_sha256=sha256_file(frontend_manifest),
        dependency_inventory_sha256=sha256_file(inventory),
    )
    (package / "release-manifest.json").write_bytes(canonical_json(manifest))

    result = verify_installation(package)

    assert result.status == "tampered"
    assert "shipped file escapes package root: linked.txt" in result.errors


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


def test_stage5_second_launcher_preserves_owner_runtime_files(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("SENTINELUEBA_RUNTIME_MODE", "desktop")
    monkeypatch.setenv("SENTINELUEBA_RUNTIME_ROOT", str(tmp_path / "runtime"))
    paths = resolve_runtime_paths()
    paths.ensure()
    status_path = paths.runtime_dir / "status.json"
    token_path = paths.runtime_dir / "control.token"
    status = status_now(
        port=8765,
        mode="desktop",
        version="0.5.0",
        state="ready",
        identity="owner",
        started_at="2026-07-28T10:00:00Z",
    )
    write_status(status_path, status)
    token_path.write_text("owner-token", encoding="utf-8")
    before_status = status_path.read_text(encoding="utf-8")
    before_token = token_path.read_text(encoding="utf-8")

    class BusyLock:
        def __init__(self, *_args: Any) -> None:
            pass

        def __enter__(self) -> None:
            raise InstanceAlreadyRunningError(status)

        def __exit__(self, *_args: Any) -> None:
            return None

    monkeypatch.setattr("sentinelueba.runtime.supervisor.SingleInstanceLock", BusyLock)

    result = run_host(open_browser=False)

    assert result.already_running is True
    assert status_path.read_text(encoding="utf-8") == before_status
    assert token_path.read_text(encoding="utf-8") == before_token


def test_stage5_service_host_disables_uvicorn_console_logging(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("PROGRAMDATA", str(tmp_path / "ProgramData"))
    captured: dict[str, object] = {}

    class FakeServer:
        def __init__(self, _config: object) -> None:
            self.should_exit = False

        def run(self) -> None:
            return None

    def fake_config(*_args: object, **kwargs: object) -> object:
        captured.update(kwargs)
        return object()

    monkeypatch.setattr("sentinelueba.runtime.supervisor.uvicorn.Config", fake_config)
    monkeypatch.setattr("sentinelueba.runtime.supervisor.uvicorn.Server", FakeServer)
    monkeypatch.setattr(
        "sentinelueba.runtime.supervisor.migrate_with_backup",
        lambda _paths: {"status": "success"},
    )
    monkeypatch.setattr(
        "sentinelueba.runtime.supervisor.check_frontend_assets",
        lambda _paths: True,
    )
    monkeypatch.setattr(
        "sentinelueba.runtime.supervisor._wait_for_server_start",
        lambda *_args: False,
    )

    result = run_host(service=True, startup_timeout_seconds=0.01)

    assert result.state == "failed"
    assert captured["log_config"] is None


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

    write_config(config_path, RuntimeConfig(runtime_mode="service", preferred_port=8767))
    loaded_mismatch, mode_warning = load_config(config_path, mode="desktop")
    assert loaded_mismatch.runtime_mode == "desktop"
    assert mode_warning is not None


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


def test_stage5_packaged_frontend_resolves_only_from_package_root(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    package = tmp_path / "package"
    package_frontend = package / "frontend"
    package_frontend.mkdir(parents=True)
    (package_frontend / "index.html").write_text("<html>packaged</html>", encoding="utf-8")
    (package_frontend / "frontend-assets.json").write_text("{}", encoding="utf-8")
    cwd = tmp_path / "empty cwd"
    cwd.mkdir()
    repo_frontend = cwd / "frontend" / "dist"
    repo_frontend.mkdir(parents=True)
    (repo_frontend / "index.html").write_text("<html>repo fallback</html>", encoding="utf-8")
    monkeypatch.chdir(cwd)
    monkeypatch.setenv("SENTINELUEBA_PACKAGED", "1")
    monkeypatch.setenv("SENTINELUEBA_PACKAGE_ROOT", str(package))

    paths = resolve_runtime_paths()

    assert frontend_dir(paths) == package_frontend
    assert check_frontend_assets(paths) is True
    (package_frontend / "index.html").unlink()
    assert check_frontend_assets(paths) is False


def test_stage5_wal_migration_backup_is_consistent(tmp_path: Path) -> None:
    monkeypatch_root = tmp_path / "runtime"
    monkeypatch_root.mkdir()
    database = monkeypatch_root / "data" / "sentinelueba.sqlite3"
    database.parent.mkdir()
    with sqlite3.connect(database) as conn:
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("CREATE TABLE schema_version(version INTEGER PRIMARY KEY, applied_at TEXT)")
        conn.execute("INSERT INTO schema_version(version, applied_at) VALUES (1, 'x')")
        conn.execute("CREATE TABLE wal_rows(value TEXT)")
        conn.execute("INSERT INTO wal_rows(value) VALUES ('from-wal')")
        conn.commit()
    paths = resolve_runtime_paths()
    object.__setattr__(paths, "root", monkeypatch_root.resolve())
    object.__setattr__(paths, "data_dir", database.parent.resolve())
    object.__setattr__(paths, "database_path", database.resolve())
    object.__setattr__(paths, "backups_dir", (monkeypatch_root / "backups").resolve())

    result = backup_before_migration(paths)

    assert result["created"] is True
    backup = paths.backups_dir / str(result["backup"])
    with sqlite3.connect(backup) as conn:
        assert conn.execute("PRAGMA integrity_check").fetchone()[0] == "ok"
        assert conn.execute("SELECT value FROM wal_rows").fetchone()[0] == "from-wal"


def test_stage5_schema_inspection_distinguishes_current_corrupt_newer_and_unreadable(
    tmp_path: Path,
) -> None:
    valid_database = tmp_path / "valid.sqlite3"
    SQLiteStorage(valid_database).initialize()
    assert inspect_schema(valid_database).status == "current_valid"

    missing_table = tmp_path / "missing-table.sqlite3"
    SQLiteStorage(missing_table).initialize()
    execute_sql(missing_table, "DROP TABLE findings")
    assert inspect_schema(missing_table).status == "current_corrupt"

    missing_index = tmp_path / "missing-index.sqlite3"
    SQLiteStorage(missing_index).initialize()
    execute_sql(missing_index, "DROP INDEX idx_findings_status")
    assert inspect_schema(missing_index).status == "current_corrupt"

    newer_database = tmp_path / "newer.sqlite3"
    execute_sql(
        newer_database,
        "CREATE TABLE schema_version(version INTEGER PRIMARY KEY, applied_at TEXT)",
        ("INSERT INTO schema_version(version, applied_at) VALUES (?, 'x')", (11,)),
    )
    newer = inspect_schema(newer_database)
    assert newer.status == "newer"
    assert newer.unsupported_newer_schema is True

    malformed = tmp_path / "malformed.sqlite3"
    malformed.write_text("not sqlite", encoding="utf-8")
    assert inspect_schema(malformed).status == "unreadable"


def test_stage5_doctor_is_read_only_and_migration_blocks_invalid_schema(
    tmp_path: Path,
) -> None:
    root = tmp_path / "runtime"
    paths = resolve_runtime_paths()
    object.__setattr__(paths, "root", root.resolve())
    object.__setattr__(paths, "config_dir", (root / "config").resolve())
    object.__setattr__(paths, "data_dir", (root / "data").resolve())
    object.__setattr__(paths, "database_path", (root / "data" / "sentinelueba.sqlite3").resolve())
    object.__setattr__(paths, "model_dir", (root / "models").resolve())
    object.__setattr__(paths, "logs_dir", (root / "logs").resolve())
    object.__setattr__(paths, "runtime_dir", (root / "runtime").resolve())
    object.__setattr__(paths, "backups_dir", (root / "backups").resolve())
    paths.ensure()
    execute_sql(
        paths.database_path,
        "CREATE TABLE schema_version(version INTEGER PRIMARY KEY, applied_at TEXT)",
        "INSERT INTO schema_version(version, applied_at) VALUES (1, 'x')",
    )
    before = paths.database_path.read_bytes()

    report = doctor(paths)

    assert report["status"] == "degraded"
    assert paths.database_path.read_bytes() == before

    object.__setattr__(paths, "database_path", (root / "data" / "valid.sqlite3").resolve())
    SQLiteStorage(paths.database_path).initialize()
    execute_sql(paths.database_path, "DROP INDEX idx_findings_status")
    migration = migrate_with_backup(paths)
    assert migration["status"] == "failed"
    assert migration["error_class"] == "SchemaIntegrityError"

    execute_sql(
        paths.database_path,
        "DELETE FROM schema_version",
        "INSERT INTO schema_version(version, applied_at) VALUES (11, 'x')",
    )
    newer = migrate_with_backup(paths)
    assert newer["status"] == "failed"
    assert newer["unsupported_newer_schema"] is True


def test_stage5_host_never_ready_for_corrupt_or_newer_database(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("SENTINELUEBA_RUNTIME_MODE", "desktop")
    monkeypatch.setenv("SENTINELUEBA_RUNTIME_ROOT", str(tmp_path / "runtime"))
    paths = resolve_runtime_paths()
    paths.ensure()
    SQLiteStorage(paths.database_path).initialize()
    execute_sql(paths.database_path, "DROP INDEX idx_findings_status")

    result = run_host(open_browser=False, startup_timeout_seconds=0.01)

    assert result.state == "failed"
    assert inspect_schema(paths.database_path).status == "current_corrupt"

    reset_runtime_context()
    newer_database = tmp_path / "runtime" / "data" / "newer.sqlite3"
    monkeypatch.setenv("SENTINELUEBA_DATABASE_PATH", str(newer_database))
    paths = resolve_runtime_paths()
    execute_sql(
        paths.database_path,
        "CREATE TABLE schema_version(version INTEGER PRIMARY KEY, applied_at TEXT)",
        "INSERT INTO schema_version(version, applied_at) VALUES (11, 'x')",
    )

    newer = run_host(open_browser=False, startup_timeout_seconds=0.01)

    assert newer.state == "failed"
    assert inspect_schema(paths.database_path).status == "newer"


def test_stage5_runtime_acl_failure_fails_closed(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("SENTINELUEBA_RUNTIME_MODE", "desktop")
    monkeypatch.setenv("SENTINELUEBA_RUNTIME_ROOT", str(tmp_path / "runtime"))
    package = tmp_path / "package"
    package.mkdir()
    monkeypatch.setenv("SENTINELUEBA_PACKAGED", "1")
    monkeypatch.setenv("SENTINELUEBA_PACKAGE_ROOT", str(package))

    def fail_acl(*_args: object, **_kwargs: object) -> dict[str, object]:
        raise PermissionError("acl denied")

    monkeypatch.setattr("sentinelueba.runtime.supervisor.protect_runtime_secret", fail_acl)

    result = run_host(open_browser=True, startup_timeout_seconds=0.01)
    paths = resolve_runtime_paths()

    assert result.state == "failed"
    assert not (paths.runtime_dir / "control.token").exists()
    assert not (paths.runtime_dir / "status.json").exists()


@pytest.mark.parametrize(
    "verification",
    [
        {"protected": False, "broad_users_read": False, "missing_expected_principals": []},
        {"protected": True, "broad_users_read": True, "missing_expected_principals": []},
        {"protected": True, "broad_users_read": False, "missing_expected_principals": ["SYSTEM"]},
    ],
)
def test_stage5_runtime_acl_negative_verification_blocks_startup(
    tmp_path: Path,
    verification: dict[str, object],
) -> None:
    calls: list[tuple[Path, str, bool]] = []

    class FakeAclAdapter:
        def protect_path(self, path: Path, *, mode: str, directory: bool) -> None:
            calls.append((path, mode, directory))

        def verify_path(self, _path: Path, *, mode: str) -> dict[str, object]:
            return {"mode": mode, **verification}

    target = tmp_path / "runtime" / "control.token"
    target.parent.mkdir(parents=True)
    target.write_text("token", encoding="utf-8")

    with pytest.raises(RuntimeAclVerificationError):
        protect_runtime_secret(target, mode="desktop", adapter=FakeAclAdapter())

    assert calls == [(target, "desktop", False)]


def test_stage5_packaged_runtime_acl_negative_verification_fails_closed(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("SENTINELUEBA_RUNTIME_MODE", "desktop")
    monkeypatch.setenv("SENTINELUEBA_RUNTIME_ROOT", str(tmp_path / "runtime"))
    package = tmp_path / "package"
    create_package_fixture(package)
    monkeypatch.setenv("SENTINELUEBA_PACKAGED", "1")
    monkeypatch.setenv("SENTINELUEBA_PACKAGE_ROOT", str(package))

    class FakeAclAdapter:
        def protect_path(self, _path: Path, *, mode: str, directory: bool) -> None:
            assert mode == "desktop"

        def verify_path(self, _path: Path, *, mode: str) -> dict[str, object]:
            return {
                "mode": mode,
                "protected": False,
                "broad_users_read": False,
                "missing_expected_principals": [],
            }

    monkeypatch.setattr("sentinelueba.runtime.security.acl_adapter", lambda: FakeAclAdapter())
    monkeypatch.setattr(
        "sentinelueba.runtime.supervisor.uvicorn.Server",
        lambda *_args: pytest.fail("host startup continued after failed ACL verification"),
    )

    result = run_host(open_browser=False, startup_timeout_seconds=0.01)
    paths = resolve_runtime_paths()

    assert result.state == "failed"
    assert not (paths.runtime_dir / "control.token").exists()
    assert not (paths.runtime_dir / "status.json").exists()


def test_stage5_packaged_runtime_acl_valid_verification_continues_startup(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("SENTINELUEBA_RUNTIME_MODE", "desktop")
    monkeypatch.setenv("SENTINELUEBA_RUNTIME_ROOT", str(tmp_path / "runtime"))
    package = tmp_path / "package"
    create_package_fixture(package)
    monkeypatch.setenv("SENTINELUEBA_PACKAGED", "1")
    monkeypatch.setenv("SENTINELUEBA_PACKAGE_ROOT", str(package))
    calls: list[tuple[Path, bool]] = []
    reached_server = False

    class FakeAclAdapter:
        def protect_path(self, path: Path, *, mode: str, directory: bool) -> None:
            assert mode == "desktop"
            calls.append((path, directory))

        def verify_path(self, _path: Path, *, mode: str) -> dict[str, object]:
            return {
                "mode": mode,
                "protected": True,
                "broad_users_read": False,
                "missing_expected_principals": [],
            }

    class FakeServer:
        def __init__(self, _config: object) -> None:
            nonlocal reached_server
            reached_server = True
            self.should_exit = False

        def run(self) -> None:
            while not self.should_exit:
                time.sleep(0.01)

    monkeypatch.setattr("sentinelueba.runtime.security.acl_adapter", lambda: FakeAclAdapter())
    monkeypatch.setattr(
        "sentinelueba.runtime.supervisor.verify_installation",
        lambda _paths: types.SimpleNamespace(status="unsigned_verified"),
    )
    monkeypatch.setattr(
        "sentinelueba.runtime.supervisor.migrate_with_backup",
        lambda _paths: {"status": "success"},
    )
    monkeypatch.setattr(
        "sentinelueba.runtime.supervisor.check_frontend_assets",
        lambda _paths: True,
    )
    monkeypatch.setattr("sentinelueba.runtime.supervisor.uvicorn.Config", lambda *a, **k: object())
    monkeypatch.setattr("sentinelueba.runtime.supervisor.uvicorn.Server", FakeServer)
    monkeypatch.setattr(
        "sentinelueba.runtime.supervisor._wait_for_server_start",
        lambda *_args: False,
    )

    result = run_host(open_browser=False, startup_timeout_seconds=0.01)

    assert result.state == "failed"
    assert reached_server is True
    assert calls


def test_stage5_windowed_host_disables_console_logging(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("SENTINELUEBA_RUNTIME_MODE", "desktop")
    monkeypatch.setenv("SENTINELUEBA_RUNTIME_ROOT", str(tmp_path / "runtime"))
    captured: dict[str, object] = {}

    class FakeServer:
        def __init__(self, _config: object) -> None:
            self.should_exit = False

        def run(self) -> None:
            return None

    def fake_config(*_args: object, **kwargs: object) -> object:
        captured.update(kwargs)
        return object()

    monkeypatch.setattr("sentinelueba.runtime.supervisor.uvicorn.Config", fake_config)
    monkeypatch.setattr("sentinelueba.runtime.supervisor.uvicorn.Server", FakeServer)
    monkeypatch.setattr(
        "sentinelueba.runtime.supervisor.migrate_with_backup",
        lambda _paths: {"status": "success"},
    )
    monkeypatch.setattr(
        "sentinelueba.runtime.supervisor.check_frontend_assets",
        lambda _paths: True,
    )
    monkeypatch.setattr(
        "sentinelueba.runtime.supervisor._wait_for_server_start",
        lambda *_args: False,
    )

    result = run_host(open_browser=False, windowed=True, startup_timeout_seconds=0.01)

    assert result.state == "failed"
    assert captured["log_config"] is None


def test_stage5_windowed_launcher_sets_stdio_before_host_import(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[dict[str, object]] = []
    fake_supervisor = types.ModuleType("sentinelueba.runtime.supervisor")

    def fake_run_host(**kwargs: object) -> HostRunResult:
        calls.append(kwargs)
        return HostRunResult("stopped", 8765, "http://127.0.0.1:8765/")

    fake_supervisor.run_host = fake_run_host  # type: ignore[attr-defined]
    monkeypatch.setitem(sys.modules, "sentinelueba.runtime.supervisor", fake_supervisor)
    launcher = load_launcher_module()
    original_stdin = sys.stdin
    original_stdout = sys.stdout
    original_stderr = sys.stderr
    monkeypatch.setattr(sys, "stdin", None)
    monkeypatch.setattr(sys, "stdout", None)
    monkeypatch.setattr(sys, "stderr", None)
    try:
        assert launcher.main() == 0
        assert sys.stdin is not None
        assert sys.stdout is not None
        assert sys.stderr is not None
    finally:
        sys.stdin = original_stdin
        sys.stdout = original_stdout
        sys.stderr = original_stderr

    assert calls == [{"open_browser": True, "windowed": True}]


@pytest.mark.parametrize(
    ("result", "expected_exit", "expected_message"),
    [
        (HostRunResult("failed", None, None), 2, True),
        (HostRunResult("ready", 8765, "http://127.0.0.1:8765/", already_running=True), 0, False),
        (HostRunResult("stopped", 8765, "http://127.0.0.1:8765/"), 0, False),
    ],
)
def test_stage5_windowed_launcher_propagates_host_result(
    result: HostRunResult,
    expected_exit: int,
    expected_message: bool,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fake_supervisor = types.ModuleType("sentinelueba.runtime.supervisor")
    fake_supervisor.run_host = lambda **_kwargs: result  # type: ignore[attr-defined]
    monkeypatch.setitem(sys.modules, "sentinelueba.runtime.supervisor", fake_supervisor)
    launcher = load_launcher_module()
    messages: list[str] = []
    monkeypatch.setattr(launcher, "_message_box", messages.append)

    exit_code = launcher.main()

    assert exit_code == expected_exit
    assert bool(messages) is expected_message
    assert all("Traceback" not in message for message in messages)
    assert all(str(Path.home()) not in message for message in messages)


def test_stage5_cli_host_run_failed_result_exits_2(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        "sentinelueba.cli.run_host",
        lambda **_kwargs: HostRunResult("failed", 8765, None),
    )
    runner = CliRunner()

    result = runner.invoke(cli_app, ["host", "run"])

    assert result.exit_code == 2
    assert '"state": "failed"' in result.output


def test_stage5_wait_for_server_start_rejects_foreign_listener() -> None:
    server, port, thread = start_health_server(body=b'{"data":{"ok":true}}')
    try:
        assert (
            _wait_for_server_start(
                FakeUvicornServer(started=False),  # type: ignore[arg-type]
                FakeServerThread(alive=True),  # type: ignore[arg-type]
                port,
                0.2,
            )
            is False
        )
    finally:
        server.shutdown()
        thread.join(timeout=5)


def test_stage5_wait_for_server_start_rejects_non_json_health() -> None:
    server, port, thread = start_health_server(body=b"ok", content_type="text/plain")
    try:
        assert (
            _wait_for_server_start(
                FakeUvicornServer(started=True),  # type: ignore[arg-type]
                FakeServerThread(alive=True),  # type: ignore[arg-type]
                port,
                0.2,
            )
            is False
        )
    finally:
        server.shutdown()
        thread.join(timeout=5)


def test_stage5_wait_for_server_start_accepts_expected_health_contract() -> None:
    server, port, thread = start_health_server(body=b'{"data":{"ok":true}}')
    try:
        assert (
            _wait_for_server_start(
                FakeUvicornServer(started=True),  # type: ignore[arg-type]
                FakeServerThread(alive=True),  # type: ignore[arg-type]
                port,
                1.0,
            )
            is True
        )
    finally:
        server.shutdown()
        thread.join(timeout=5)


def test_stage5_wait_for_server_start_rejects_exited_thread() -> None:
    assert (
        _wait_for_server_start(
            FakeUvicornServer(started=True),  # type: ignore[arg-type]
            FakeServerThread(alive=False),  # type: ignore[arg-type]
            9,
            0.2,
        )
        is False
    )


def test_stage5_wait_for_server_start_times_out_without_health() -> None:
    assert (
        _wait_for_server_start(
            FakeUvicornServer(started=True),  # type: ignore[arg-type]
            FakeServerThread(alive=True),  # type: ignore[arg-type]
            9,
            0.2,
        )
        is False
    )


def test_stage5_service_host_failed_result_reports_scm_failure(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from sentinelueba.runtime import service as service_module

    events: list[tuple[str, str]] = []
    logs: list[str] = []
    reports: list[str] = []
    monkeypatch.setattr(
        service_module,
        "run_host",
        lambda **_kwargs: HostRunResult("failed", None, None),
    )
    monkeypatch.setattr(
        service_module,
        "_write_service_failure_log",
        lambda event, *, error_class: events.append((event, error_class)),
    )

    with pytest.raises(ServiceStartupFailed):
        _run_service_host_or_raise(
            log_error=logs.append,
            report_failure=lambda: reports.append("failed"),
        )

    assert events == [("service_host_failed", "HostFailed")]
    assert logs == ["SentinelUEBA service host failed safely"]
    assert reports == ["failed"]


def test_stage5_service_host_non_failed_result_returns_cleanly(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from sentinelueba.runtime import service as service_module

    monkeypatch.setattr(
        service_module,
        "run_host",
        lambda **_kwargs: HostRunResult("stopped", 8765, "http://127.0.0.1:8765/"),
    )

    _run_service_host_or_raise(log_error=lambda _message: pytest.fail("unexpected error log"))


def test_stage5_config_log_level_controls_runtime_file_logger(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import logging

    monkeypatch.setenv("SENTINELUEBA_RUNTIME_MODE", "desktop")
    monkeypatch.setenv("SENTINELUEBA_RUNTIME_ROOT", str(tmp_path / "runtime"))
    paths = resolve_runtime_paths()
    write_config(
        paths.config_dir / "config.json",
        RuntimeConfig(runtime_mode="desktop", log_level="ERROR"),
    )
    monkeypatch.setattr(
        "sentinelueba.runtime.supervisor.migrate_with_backup",
        lambda _paths: {"status": "failed"},
    )

    run_host(open_browser=False, startup_timeout_seconds=0.01)

    assert logging.getLogger("sentinelueba").level == logging.ERROR


def test_stage5_service_failure_log_is_safe(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from sentinelueba.runtime.service import _write_service_failure_log

    monkeypatch.setenv("PROGRAMDATA", str(tmp_path / "ProgramData"))

    _write_service_failure_log("service_host_exception", error_class="RuntimeError")

    payload = json.loads(
        (tmp_path / "ProgramData" / "SentinelUEBA" / "logs" / "service-failure.log").read_text(
            encoding="utf-8",
        )
    )
    blob = json.dumps(payload)
    assert payload["event"] == "service_host_exception"
    assert payload["error_class"] == "RuntimeError"
    assert "Traceback" not in blob
    assert str(tmp_path) not in blob


def test_stage5_service_unsupported_platform_is_safe() -> None:
    if os.name == "nt":
        pytest.skip("unsupported platform path is non-Windows only")
    adapter = UnsupportedServiceAdapter()
    assert adapter.status() == "unsupported"
    with pytest.raises(RuntimeError):
        install_service(confirm=True, adapter=adapter)


def test_stage5_service_debug_contract_mentions_localservice() -> None:
    from sentinelueba.runtime.service import run_service_debug_smoke

    smoke = run_service_debug_smoke()
    assert smoke["service"] == "SentinelUEBA"
    assert smoke["account"] == SERVICE_ACCOUNT


def test_stage5_pywin32_adapter_installs_real_scm_service(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[tuple[str, object]] = []

    fake_win32service = types.SimpleNamespace(
        SC_MANAGER_CREATE_SERVICE=1,
        SERVICE_ALL_ACCESS=2,
        SERVICE_WIN32_OWN_PROCESS=3,
        SERVICE_DEMAND_START=4,
        SERVICE_ERROR_NORMAL=5,
        SERVICE_CHANGE_CONFIG=6,
        SERVICE_CONFIG_FAILURE_ACTIONS=7,
        SC_ACTION_RESTART=8,
        SC_ACTION_NONE=9,
        OpenSCManager=lambda *args: calls.append(("open_manager", args)) or "manager",
        CreateService=lambda *args: calls.append(("create_service", args)) or "service",
        CloseServiceHandle=lambda handle: calls.append(("close", handle)),
        ChangeServiceConfig2=lambda *args: calls.append(("recovery", args)),
    )
    fake_service_util = types.SimpleNamespace(
        QueryServiceStatus=lambda *_args: (_ for _ in ()).throw(RuntimeError("missing")),
        SmartOpenService=lambda *args: calls.append(("smart_open", args)) or "recovery-service",
        StartService=lambda *_args: None,
        StopService=lambda *_args: None,
        RemoveService=lambda *_args: None,
    )
    monkeypatch.setitem(sys.modules, "win32service", fake_win32service)
    monkeypatch.setitem(sys.modules, "win32serviceutil", fake_service_util)

    PyWin32ServiceAdapter().install(tmp_path / "SentinelUEBAService.exe")

    create = next(call for call in calls if call[0] == "create_service")
    args = create[1]
    assert args[1] == SERVICE_ID
    assert args[2] == SERVICE_DISPLAY_NAME
    assert args[4] == fake_win32service.SERVICE_WIN32_OWN_PROCESS
    assert args[5] == fake_win32service.SERVICE_DEMAND_START
    assert str(args[7]).startswith('"')
    assert str(args[7]).endswith('SentinelUEBAService.exe"')
    assert args[11] == SERVICE_ACCOUNT
    recovery = next(call for call in calls if call[0] == "recovery")
    actions = recovery[1][2]["Actions"]
    assert actions[:3] == [(fake_win32service.SC_ACTION_RESTART, 60_000)] * 3
    assert actions[3] == (fake_win32service.SC_ACTION_NONE, 0)


def test_stage5_service_recovery_actions_restart_three_times_then_stop() -> None:
    fake_win32service = types.SimpleNamespace(SC_ACTION_RESTART=8, SC_ACTION_NONE=9)

    actions = service_recovery_actions(fake_win32service)

    assert actions == [
        (fake_win32service.SC_ACTION_RESTART, 60_000),
        (fake_win32service.SC_ACTION_RESTART, 60_000),
        (fake_win32service.SC_ACTION_RESTART, 60_000),
        (fake_win32service.SC_ACTION_NONE, 0),
    ]


def test_stage5_pywin32_adapter_recovery_failure_blocks_install(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    state = install_fake_scm_modules(monkeypatch, fail_recovery=True)
    calls = state["calls"]

    with pytest.raises(RuntimeError, match="service recovery policy was not configured"):
        PyWin32ServiceAdapter().install(tmp_path / "SentinelUEBAService.exe")

    assert state["installed"] is False
    assert state["deleted"] is True
    assert any(call[0] == "delete_service" for call in calls)
    assert any(call[0] == "recovery" for call in calls)
    assert ("close", "service-handle") in calls
    assert ("close", "service") in calls
    assert ("close", "manager") in calls


def test_stage5_service_recovery_failure_rollback_allows_repeat_install(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    state = install_fake_scm_modules(monkeypatch, fail_recovery=True)
    adapter = PyWin32ServiceAdapter()
    binary = tmp_path / "SentinelUEBAService.exe"

    with pytest.raises(RuntimeError, match="service recovery policy was not configured"):
        adapter.install(binary)

    assert adapter.is_installed() is False
    state["fail_recovery"] = False
    result = adapter.install(binary)

    assert result["already_installed"] is False
    assert result["recovery_configured"] is True
    assert adapter.is_installed() is True
    assert state["created"] == 2


def test_stage5_service_recovery_rollback_failure_is_explicit(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    state = install_fake_scm_modules(monkeypatch, fail_recovery=True, fail_delete=True)

    with pytest.raises(
        RuntimeError,
        match="service installation failed and rollback was incomplete",
    ):
        PyWin32ServiceAdapter().install(tmp_path / "SentinelUEBAService.exe")

    assert state["installed"] is True
    assert state["deleted"] is False


def test_stage5_service_rollback_does_not_delete_user_data(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    state = install_fake_scm_modules(monkeypatch, fail_recovery=True)
    data_file = tmp_path / "runtime" / "data" / "sentinelueba.sqlite3"
    data_file.parent.mkdir(parents=True)
    data_file.write_text("user data", encoding="utf-8")

    with pytest.raises(RuntimeError, match="service recovery policy was not configured"):
        PyWin32ServiceAdapter().install(tmp_path / "SentinelUEBAService.exe")

    assert state["installed"] is False
    assert data_file.read_text(encoding="utf-8") == "user data"


def test_stage5_existing_service_idempotent_success(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fake_win32service = types.SimpleNamespace(SC_ACTION_RESTART=8, SC_ACTION_NONE=9)
    binary = tmp_path / "SentinelUEBAService.exe"
    state = install_fake_scm_modules(
        monkeypatch,
        installed=True,
        binary_path=str(binary),
        account=SERVICE_ACCOUNT,
        start_type=4,
        service_type=3,
        recovery_actions=service_recovery_actions(fake_win32service),
    )

    result = PyWin32ServiceAdapter().install(binary)

    assert result == {
        "service": SERVICE_ID,
        "status": "4",
        "binary": "SentinelUEBAService.exe",
        "already_installed": True,
        "recovery_configured": True,
        "account": SERVICE_ACCOUNT,
        "start_type": "manual",
    }
    assert state["created"] == 0


@pytest.mark.parametrize(
    ("override", "expected_error"),
    [
        ({"recovery_actions": None}, "recovery_policy"),
        ({"binary_path": r"C:\Other\OtherService.exe"}, "binary"),
        ({"account": r"LocalSystem"}, "account"),
        ({"start_type": 2}, "start_type"),
        ({"service_type": 16}, "service_type"),
    ],
)
def test_stage5_existing_service_validation_rejects_unsafe_config(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    override: dict[str, object],
    expected_error: str,
) -> None:
    fake_win32service = types.SimpleNamespace(SC_ACTION_RESTART=8, SC_ACTION_NONE=9)
    binary = tmp_path / "SentinelUEBAService.exe"
    config = {
        "installed": True,
        "binary_path": str(binary),
        "account": SERVICE_ACCOUNT,
        "start_type": 4,
        "service_type": 3,
        "recovery_actions": service_recovery_actions(fake_win32service),
    }
    config.update(override)
    state = install_fake_scm_modules(monkeypatch, **config)

    with pytest.raises(RuntimeError, match=expected_error):
        PyWin32ServiceAdapter().install(binary)

    assert state["created"] == 0
    assert state["installed"] is True


def test_stage5_service_dispatcher_and_management_paths_are_mockable(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from sentinelueba.runtime import service as service_module

    calls: list[tuple[str, object]] = []

    fake_service_manager = types.SimpleNamespace(
        Initialize=lambda *args: calls.append(("initialize", args)),
        PrepareToHostSingle=lambda service_class: calls.append(("prepare", service_class)),
        StartServiceCtrlDispatcher=lambda: calls.append(("dispatch", None)),
    )
    fake_service_util = types.SimpleNamespace(
        HandleCommandLine=lambda service_class: calls.append(("handle", service_class))
    )
    monkeypatch.setattr(service_module.os, "name", "nt", raising=False)
    monkeypatch.setitem(sys.modules, "servicemanager", fake_service_manager)
    monkeypatch.setitem(sys.modules, "win32serviceutil", fake_service_util)

    service_module.dispatch_service()
    service_module.handle_service_command_line()

    assert calls[0][0] == "initialize"
    assert calls[1] == ("prepare", service_module.SentinelUEBAWindowsService)
    assert calls[2] == ("dispatch", None)
    assert calls[3] == ("handle", service_module.SentinelUEBAWindowsService)


def test_stage5_import_data_rejects_symlink_escape_and_secret(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    source = tmp_path / "source"
    source.mkdir()
    (source / "event.json").write_text("{}", encoding="utf-8")
    (source / "control.token").write_text("secret", encoding="utf-8")
    outside = tmp_path / "outside.secret"
    outside.write_text("secret", encoding="utf-8")
    with suppress(OSError):
        (source / "linked.txt").symlink_to(outside)
    monkeypatch.setenv("SENTINELUEBA_RUNTIME_MODE", "desktop")
    monkeypatch.setenv("SENTINELUEBA_RUNTIME_ROOT", str(tmp_path / "runtime"))
    paths = resolve_runtime_paths()

    result = __import__(
        "sentinelueba.runtime.import_data",
        fromlist=["import_data"],
    ).import_data(source, paths, confirm=True)

    assert result["imported"] == 1
    assert result["partial"] is True
    assert not (paths.data_dir / "control.token").exists()
    assert not (paths.data_dir / "linked.txt").exists()
