from __future__ import annotations

import json
import time
from datetime import datetime
from pathlib import Path

import httpx
import typer
import uvicorn

from sentinelueba import __version__
from sentinelueba.api.main import app as fastapi_app
from sentinelueba.config import get_settings
from sentinelueba.runtime.diagnostics import doctor, exit_code
from sentinelueba.runtime.import_data import import_data, preview_import
from sentinelueba.runtime.installation import verify_installation
from sentinelueba.runtime.paths import resolve_runtime_paths
from sentinelueba.runtime.service import (
    install_service,
    run_service_debug_smoke,
    service_adapter,
    uninstall_service,
)
from sentinelueba.runtime.supervisor import host_status, run_host
from sentinelueba.services.pipeline import DemoPipeline

app = typer.Typer(help="SentinelUEBA local-first UEBA CLI.")
host_app = typer.Typer(help="Local packaged host supervisor commands.")
runtime_app = typer.Typer(help="Runtime data management commands.")
service_app = typer.Typer(help="Optional Windows Service commands.")
features_app = typer.Typer(help="Materialized feature store commands.")
datasets_app = typer.Typer(help="Immutable dataset snapshot commands.")
retention_app = typer.Typer(help="Local retention policy commands.")
quarantine_app = typer.Typer(help="Quarantine inspection commands.")
ml_app = typer.Typer(help="Stage 3 ML pipeline commands.")
ml_runs_app = typer.Typer(help="ML training run commands.")
ml_models_app = typer.Typer(help="ML model registry commands.")
ml_scoring_app = typer.Typer(help="Offline scoring run commands.")
detection_app = typer.Typer(help="Stage 4 detection engine commands.")
detection_policies_app = typer.Typer(help="Detection policy commands.")
detection_rules_app = typer.Typer(help="Detection rule commands.")
detection_runs_app = typer.Typer(help="Detection run commands.")
detection_findings_app = typer.Typer(help="Finding lifecycle commands.")
detection_suppressions_app = typer.Typer(help="Detection suppression commands.")
detection_worker_app = typer.Typer(help="Controlled local detection worker commands.")
app.add_typer(host_app, name="host")
app.add_typer(runtime_app, name="runtime")
app.add_typer(service_app, name="service")
app.add_typer(features_app, name="features")
app.add_typer(datasets_app, name="datasets")
app.add_typer(retention_app, name="retention")
app.add_typer(quarantine_app, name="quarantine")
app.add_typer(ml_app, name="ml")
app.add_typer(detection_app, name="detection")
ml_app.add_typer(ml_runs_app, name="runs")
ml_app.add_typer(ml_models_app, name="models")
ml_app.add_typer(ml_scoring_app, name="scoring-runs")
detection_app.add_typer(detection_policies_app, name="policies")
detection_app.add_typer(detection_rules_app, name="rules")
detection_app.add_typer(detection_runs_app, name="runs")
detection_app.add_typer(detection_findings_app, name="findings")
detection_app.add_typer(detection_suppressions_app, name="suppressions")
detection_app.add_typer(detection_worker_app, name="worker")


@app.callback()
def main(
    version: bool = typer.Option(
        False,
        "--version",
        help="Show SentinelUEBA version and exit.",
        is_eager=True,
    ),
) -> None:
    if version:
        typer.echo(f"SentinelUEBA {__version__}")
        raise typer.Exit()


def _pipeline() -> DemoPipeline:
    return DemoPipeline(get_settings())


def _print(payload: object) -> None:
    typer.echo(json.dumps(payload, indent=2, default=str))


def _parse_if_max_samples(value: str) -> str | int | float:
    if value == "auto":
        return value
    try:
        if "." in value:
            parsed_float = float(value)
            if 0 < parsed_float <= 1:
                return parsed_float
        else:
            parsed_int = int(value)
            if parsed_int >= 1:
                return parsed_int
    except ValueError as exc:
        raise typer.BadParameter("must be auto, a positive int, or a float in (0, 1]") from exc
    raise typer.BadParameter("must be auto, a positive int, or a float in (0, 1]")


def _parse_datetime(value: str | None) -> datetime | None:
    if value is None:
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise typer.BadParameter("must be an ISO-8601 datetime") from exc


def _runtime_paths() -> object:
    paths = resolve_runtime_paths()
    paths.ensure()
    return paths


@app.command()
def init() -> None:
    """Initialize local SQLite schema and artifact directories."""
    _print(_pipeline().initialize())


@app.command("verify-installation")
def verify_installation_command() -> None:
    """Verify packaged files against release-manifest.json."""
    result = verify_installation(resolve_runtime_paths().package_dir)
    _print(result.safe_dict())
    if result.status not in {"verified", "unsigned_verified"}:
        raise typer.Exit(code=2)


@host_app.command("run")
def host_run(open_browser: bool = typer.Option(False, "--open-browser")) -> None:
    """Run the local loopback host supervisor."""
    result = run_host(open_browser=open_browser)
    _print(result.safe_dict())


@host_app.command("status")
def host_status_command() -> None:
    """Show safe local host state."""
    _print(host_status(resolve_runtime_paths()))


@host_app.command("open")
def host_open() -> None:
    """Open the browser for the existing local host."""
    status_payload = host_status(resolve_runtime_paths())
    port = status_payload.get("port")
    if not isinstance(port, int):
        typer.echo("host is not running", err=True)
        raise typer.Exit(code=2)
    import webbrowser

    webbrowser.open(f"http://127.0.0.1:{port}/")
    _print({"opened": True, "port": port})


@host_app.command("stop")
def host_stop(confirm: bool = typer.Option(False, "--confirm")) -> None:
    """Gracefully stop the desktop local host."""
    if not confirm:
        typer.echo("host stop requires --confirm", err=True)
        raise typer.Exit(code=2)
    paths = resolve_runtime_paths()
    status_payload = host_status(paths)
    port = status_payload.get("port")
    if not isinstance(port, int):
        _print({"state": "stopped"})
        return
    token_path = paths.runtime_dir / "control.token"
    try:
        token = token_path.read_text(encoding="utf-8")
    except FileNotFoundError as exc:
        typer.echo("control token is not available", err=True)
        raise typer.Exit(code=2) from exc
    response = httpx.post(
        f"http://127.0.0.1:{port}/runtime/shutdown",
        headers={"X-SentinelUEBA-Control-Token": token},
        json={"confirm": True},
        timeout=5,
    )
    _print({"status_code": response.status_code, "body": response.json()})
    if response.status_code >= 400:
        raise typer.Exit(code=2)


@host_app.command("doctor")
def host_doctor() -> None:
    """Run safe runtime diagnostics."""
    report = doctor(resolve_runtime_paths())
    _print(report)
    raise typer.Exit(code=exit_code(report))


@runtime_app.command("import-data")
def runtime_import_data(
    source: Path = typer.Option(..., "--source"),
    confirm: bool = typer.Option(False, "--confirm"),
) -> None:
    """Preview or import prior runtime data into the managed runtime root."""
    paths = resolve_runtime_paths()
    if not confirm:
        _print(preview_import(source))
        raise typer.Exit(code=2)
    _print(import_data(source, paths, confirm=confirm))


@service_app.command("install")
def service_install(confirm: bool = typer.Option(False, "--confirm")) -> None:
    """Install optional Windows Service; Windows admin only."""
    try:
        _print(install_service(confirm=confirm))
    except (PermissionError, RuntimeError, ValueError) as exc:
        typer.echo(str(exc), err=True)
        raise typer.Exit(code=2) from exc


@service_app.command("uninstall")
def service_uninstall(confirm: bool = typer.Option(False, "--confirm")) -> None:
    """Uninstall optional Windows Service without deleting user data."""
    try:
        _print(uninstall_service(confirm=confirm))
    except (RuntimeError, ValueError) as exc:
        typer.echo(str(exc), err=True)
        raise typer.Exit(code=2) from exc


@service_app.command("start")
def service_start() -> None:
    """Start optional Windows Service."""
    adapter = service_adapter()
    try:
        adapter.start()
        _print({"service": "SentinelUEBA", "status": adapter.status()})
    except RuntimeError as exc:
        typer.echo(str(exc), err=True)
        raise typer.Exit(code=2) from exc


@service_app.command("stop")
def service_stop(confirm: bool = typer.Option(False, "--confirm")) -> None:
    """Stop optional Windows Service."""
    if not confirm:
        typer.echo("service stop requires --confirm", err=True)
        raise typer.Exit(code=2)
    adapter = service_adapter()
    try:
        adapter.stop()
        _print({"service": "SentinelUEBA", "status": adapter.status()})
    except RuntimeError as exc:
        typer.echo(str(exc), err=True)
        raise typer.Exit(code=2) from exc


@service_app.command("restart")
def service_restart(confirm: bool = typer.Option(False, "--confirm")) -> None:
    """Restart optional Windows Service."""
    if not confirm:
        typer.echo("service restart requires --confirm", err=True)
        raise typer.Exit(code=2)
    adapter = service_adapter()
    try:
        adapter.stop()
        adapter.start()
        _print({"service": "SentinelUEBA", "status": adapter.status()})
    except RuntimeError as exc:
        typer.echo(str(exc), err=True)
        raise typer.Exit(code=2) from exc


@service_app.command("status")
def service_status() -> None:
    """Show optional Windows Service status."""
    adapter = service_adapter()
    _print({"service": "SentinelUEBA", "status": adapter.status()})


@service_app.command("logs")
def service_logs() -> None:
    """Show safe service log location hint."""
    _print({"logs": service_adapter().logs()})


@service_app.command("debug-smoke")
def service_debug_smoke() -> None:
    """Validate service entry metadata without SCM install."""
    _print(run_service_debug_smoke())


@app.command("generate-demo")
def generate_demo(seed: int = 42) -> None:
    """Generate a synthetic 24-hour-equivalent telemetry dataset."""
    _print(_pipeline().generate_demo_data(seed=seed))


@app.command()
def train(seed: int = 42) -> None:
    """Train the PyTorch autoencoder on normal demo windows."""
    try:
        _print(_pipeline().train(seed=seed))
    except ValueError as exc:
        typer.echo(str(exc), err=True)
        raise typer.Exit(code=2) from exc


@app.command("train-real")
def train_real(seed: int = 42) -> None:
    """Train a real-data model only after the real training gate is satisfied."""
    try:
        _print(_pipeline().train(seed=seed, dataset_kind="real"))
    except ValueError as exc:
        typer.echo(str(exc), err=True)
        raise typer.Exit(code=2) from exc


@app.command()
def detect() -> None:
    """Run anomaly detection and persist anomaly records."""
    try:
        _print(_pipeline().detect())
    except FileNotFoundError as exc:
        typer.echo(f"model is not available: {exc}", err=True)
        raise typer.Exit(code=2) from exc


@app.command()
def status() -> None:
    """Show project, storage, and model status."""
    _print(_pipeline().status())


@app.command()
def clean() -> None:
    """Remove synthetic demo data and local model artifacts."""
    _print(_pipeline().clean())


@app.command()
def capabilities() -> None:
    """Show collector capabilities and privilege requirements."""
    _print({"collectors": _pipeline().collector_capabilities()})


@app.command()
def collect(duration: int | None = None, interval: float = 5.0) -> None:
    """Start opt-in Windows telemetry collection."""
    try:
        _print(_pipeline().start_collection(duration_seconds=duration, interval_seconds=interval))
        deadline = time.monotonic() + duration if duration is not None else None
        while True:
            status_payload = _pipeline().collection_status()
            if not bool(status_payload["running"]):
                _print(status_payload)
                break
            if deadline is not None and time.monotonic() >= deadline + 1:
                _print(status_payload)
                break
            time.sleep(min(max(interval, 0.5), 5.0))
    except KeyboardInterrupt:
        _print(_pipeline().stop_collection())
        raise typer.Exit(code=130) from None
    except ValueError as exc:
        typer.echo(str(exc), err=True)
        raise typer.Exit(code=2) from exc


@app.command("stop-collection")
def stop_collection() -> None:
    """Stop an active collection session."""
    _print(_pipeline().stop_collection())


@app.command("collector-status")
def collector_status() -> None:
    """Show active collector status and progress."""
    _print(_pipeline().collection_status())


@app.command("collection-sessions")
def collection_sessions() -> None:
    """List stored collection sessions."""
    _print({"sessions": _pipeline().collection_sessions()})


@app.command("training-eligibility")
def training_eligibility(dataset: str = "real") -> None:
    """Check whether a dataset is eligible for model training."""
    result = _pipeline().training_eligibility(dataset)
    _print(result)
    if not bool(result["eligible"]):
        raise typer.Exit(code=1)


@app.command("data-quality")
def data_quality() -> None:
    """Compute data quality, coverage, quarantine, and readiness summary."""
    _print(_pipeline().data_quality())


@features_app.command("materialize")
def features_materialize(dataset: str = "synthetic") -> None:
    """Incrementally materialize 15-minute feature windows."""
    _print(_pipeline().materialize_features(dataset))


@features_app.command("rebuild")
def features_rebuild(dataset: str = "synthetic") -> None:
    """Fully rebuild feature windows for one dataset kind."""
    _print(_pipeline().rebuild_features(dataset))


@features_app.command("status")
def features_status() -> None:
    """Show materialization watermark and feature window counts."""
    _print(_pipeline().features_status())


@datasets_app.command("create")
def datasets_create(kind: str = typer.Option("synthetic", "--kind")) -> None:
    """Create an immutable Parquet dataset snapshot."""
    try:
        _print(_pipeline().create_dataset(kind))
    except ValueError as exc:
        typer.echo(str(exc), err=True)
        raise typer.Exit(code=2) from exc


@datasets_app.command("list")
def datasets_list(kind: str | None = typer.Option(None, "--kind")) -> None:
    """List known dataset snapshots."""
    _print(_pipeline().list_datasets(kind))


@datasets_app.command("show")
def datasets_show(dataset_id: str) -> None:
    """Show dataset snapshot manifest."""
    try:
        _print(_pipeline().show_dataset(dataset_id))
    except ValueError as exc:
        typer.echo(str(exc), err=True)
        raise typer.Exit(code=2) from exc


@datasets_app.command("verify")
def datasets_verify(dataset_id: str) -> None:
    """Verify snapshot manifest and Parquet checksums."""
    try:
        _print(_pipeline().verify_dataset(dataset_id))
    except ValueError as exc:
        typer.echo(str(exc), err=True)
        raise typer.Exit(code=2) from exc


@retention_app.command("preview")
def retention_preview() -> None:
    """Preview local retention policy without deleting data."""
    _print(_pipeline().retention_preview())


@retention_app.command("apply")
def retention_apply(confirm: bool = typer.Option(False, "--confirm")) -> None:
    """Apply local retention policy; snapshots and models are never deleted."""
    if not confirm:
        typer.echo("retention apply requires --confirm", err=True)
        raise typer.Exit(code=2)
    _print(_pipeline().retention_apply())


@quarantine_app.command("summary")
def quarantine_summary() -> None:
    """Summarize quarantined validation failures."""
    _print(_pipeline().quarantine_summary())


@ml_app.command("status")
def ml_status() -> None:
    """Show model registry, champions, and scoring status."""
    _print(_pipeline().ml_status())


@ml_app.command("train")
def ml_train(
    dataset: str = typer.Option("synthetic", "--dataset"),
    dataset_id: str | None = typer.Option(None, "--dataset-id"),
    families: str = typer.Option("autoencoder,isolation-forest", "--families"),
    seed: int = 42,
    target_fpr: float = typer.Option(0.05, "--target-fpr"),
    autoencoder_epochs: int = typer.Option(80, "--autoencoder-epochs", min=1, max=300),
    autoencoder_batch_size: int = typer.Option(
        16,
        "--autoencoder-batch-size",
        min=1,
        max=4096,
    ),
    autoencoder_learning_rate: float = typer.Option(
        0.005,
        "--autoencoder-learning-rate",
        min=0.000001,
        max=1.0,
    ),
    autoencoder_weight_decay: float = typer.Option(
        0.0001,
        "--autoencoder-weight-decay",
        min=0.0,
        max=1.0,
    ),
    autoencoder_hidden_dim: int = typer.Option(10, "--autoencoder-hidden-dim", min=2, max=256),
    autoencoder_latent_dim: int = typer.Option(4, "--autoencoder-latent-dim", min=1, max=128),
    autoencoder_plateau_patience: int = typer.Option(
        12,
        "--autoencoder-plateau-patience",
        min=1,
        max=100,
    ),
    if_n_estimators: int = typer.Option(80, "--if-n-estimators", min=10, max=500),
    if_max_samples: str = typer.Option("auto", "--if-max-samples"),
    if_max_features: float = typer.Option(1.0, "--if-max-features", min=0.000001, max=1.0),
    if_bootstrap: bool = typer.Option(False, "--if-bootstrap"),
    if_n_jobs: int = typer.Option(1, "--if-n-jobs", min=1, max=2),
) -> None:
    """Train Stage 3 candidate model families from a registered snapshot."""
    try:
        selected = [item.strip() for item in families.split(",") if item.strip()]
        _print(
            _pipeline().ml_train(
                dataset_kind=dataset,
                dataset_id=dataset_id,
                families=selected,
                seed=seed,
                target_fpr=target_fpr,
                autoencoder_config={
                    "epochs": autoencoder_epochs,
                    "batch_size": autoencoder_batch_size,
                    "learning_rate": autoencoder_learning_rate,
                    "weight_decay": autoencoder_weight_decay,
                    "hidden_dim": autoencoder_hidden_dim,
                    "latent_dim": autoencoder_latent_dim,
                    "plateau_patience": autoencoder_plateau_patience,
                },
                isolation_forest_config={
                    "n_estimators": if_n_estimators,
                    "max_samples": _parse_if_max_samples(if_max_samples),
                    "max_features": if_max_features,
                    "bootstrap": if_bootstrap,
                    "n_jobs": if_n_jobs,
                },
            )
        )
    except ValueError as exc:
        typer.echo(str(exc), err=True)
        raise typer.Exit(code=2) from exc


@ml_runs_app.command("list")
def ml_runs_list() -> None:
    """List ML training runs."""
    _print({"training_runs": _pipeline().ml_training_runs()})


@ml_runs_app.command("show")
def ml_runs_show(training_run_id: str) -> None:
    """Show one ML training run."""
    run = _pipeline().ml_training_run(training_run_id)
    if run is None:
        typer.echo("training run not found", err=True)
        raise typer.Exit(code=2)
    _print(run)


@ml_models_app.command("list")
def ml_models_list() -> None:
    """List registered model bundles."""
    _print({"models": _pipeline().ml_models()})


@ml_models_app.command("show")
def ml_models_show(model_id: str) -> None:
    """Show registered model metadata."""
    try:
        _print(_pipeline().ml_model(model_id))
    except ValueError as exc:
        typer.echo(str(exc), err=True)
        raise typer.Exit(code=2) from exc


@ml_models_app.command("verify")
def ml_models_verify(model_id: str) -> None:
    """Verify immutable model bundle and registry metadata."""
    try:
        _print(_pipeline().ml_verify_model(model_id))
    except ValueError as exc:
        typer.echo(str(exc), err=True)
        raise typer.Exit(code=2) from exc


@ml_models_app.command("compare")
def ml_models_compare(model_id: str, other_model_id: str) -> None:
    """Compare two registered model candidates."""
    _print(_pipeline().ml_compare_models([model_id, other_model_id]))


@ml_models_app.command("promote")
def ml_models_promote(
    model_id: str,
    confirm: bool = typer.Option(False, "--confirm"),
    reason: str = typer.Option("manual promotion", "--reason"),
) -> None:
    """Promote a verified model to champion."""
    try:
        _print(_pipeline().ml_promote_model(model_id, confirm=confirm, reason=reason))
    except ValueError as exc:
        typer.echo(str(exc), err=True)
        raise typer.Exit(code=2) from exc


@ml_models_app.command("recommend")
def ml_models_recommend(
    model_id: str,
    confirm: bool = typer.Option(False, "--confirm"),
    reason: str = typer.Option("manual recommendation", "--reason"),
) -> None:
    """Mark a verified candidate as recommended."""
    try:
        _print(_pipeline().ml_recommend_model(model_id, confirm=confirm, reason=reason))
    except ValueError as exc:
        typer.echo(str(exc), err=True)
        raise typer.Exit(code=2) from exc


@ml_models_app.command("retire")
def ml_models_retire(
    model_id: str,
    confirm: bool = typer.Option(False, "--confirm"),
    reason: str = typer.Option("manual retirement", "--reason"),
) -> None:
    """Retire a registered model without deleting artifacts."""
    try:
        _print(_pipeline().ml_retire_model(model_id, confirm=confirm, reason=reason))
    except ValueError as exc:
        typer.echo(str(exc), err=True)
        raise typer.Exit(code=2) from exc


@ml_models_app.command("rollback")
def ml_models_rollback(
    model_id: str,
    confirm: bool = typer.Option(False, "--confirm"),
    reason: str = typer.Option("manual rollback", "--reason"),
) -> None:
    """Promote a previously verified retired model back to champion."""
    try:
        _print(_pipeline().ml_rollback_model(model_id, confirm=confirm, reason=reason))
    except ValueError as exc:
        typer.echo(str(exc), err=True)
        raise typer.Exit(code=2) from exc


@ml_app.command("evaluate")
def ml_evaluate(model_id: str) -> None:
    """Show latest evaluation for a registered model."""
    _print(_pipeline().ml_evaluate_model(model_id))


@ml_app.command("score")
def ml_score(
    dataset_id: str = typer.Option(..., "--dataset"),
    model_id: str | None = typer.Option(None, "--model"),
    batch_size: int = typer.Option(256, "--batch-size", min=1, max=4096),
) -> None:
    """Run controlled offline scoring against a registered snapshot."""
    try:
        _print(
            _pipeline().ml_score(
                dataset_id=dataset_id,
                model_id=model_id,
                batch_size=batch_size,
            )
        )
    except ValueError as exc:
        typer.echo(str(exc), err=True)
        raise typer.Exit(code=2) from exc


@ml_scoring_app.command("list")
def ml_scoring_runs_list() -> None:
    """List offline scoring runs."""
    _print({"scoring_runs": _pipeline().ml_scoring_runs()})


@ml_scoring_app.command("show")
def ml_scoring_runs_show(scoring_run_id: str) -> None:
    """Show one offline scoring run."""
    run = _pipeline().ml_scoring_run(scoring_run_id)
    if run is None:
        typer.echo("scoring run not found", err=True)
        raise typer.Exit(code=2)
    _print(run)


@ml_app.command("drift")
def ml_drift(
    model_id: str = typer.Option(..., "--model"),
    dataset_id: str = typer.Option(..., "--dataset"),
) -> None:
    """Compare a model training snapshot to another registered snapshot."""
    try:
        _print(_pipeline().ml_drift(model_id=model_id, dataset_id=dataset_id))
    except ValueError as exc:
        typer.echo(str(exc), err=True)
        raise typer.Exit(code=2) from exc


@detection_app.command("status")
def detection_status() -> None:
    """Show Stage 4 detection policy, worker, watermark, and finding state."""
    _print(_pipeline().detection_status())


@detection_policies_app.command("list")
def detection_policies_list() -> None:
    """List immutable detection policies."""
    _print({"policies": _pipeline().detection_policies()})


@detection_policies_app.command("show")
def detection_policies_show(
    policy_id: str,
    version: str | None = typer.Option(None, "--version"),
) -> None:
    """Show one immutable detection policy."""
    try:
        _print(_pipeline().detection_policy(policy_id, version))
    except ValueError as exc:
        typer.echo(str(exc), err=True)
        raise typer.Exit(code=2) from exc


@detection_policies_app.command("activate")
def detection_policies_activate(
    policy_id: str,
    version: str | None = typer.Option(None, "--version"),
    confirm: bool = typer.Option(False, "--confirm"),
    reason: str = typer.Option("manual policy activation", "--reason"),
) -> None:
    """Activate a registered immutable detection policy."""
    try:
        _print(
            _pipeline().detection_activate_policy(
                policy_id,
                version,
                confirm=confirm,
                reason=reason,
            )
        )
    except ValueError as exc:
        typer.echo(str(exc), err=True)
        raise typer.Exit(code=2) from exc


@detection_rules_app.command("list")
def detection_rules_list() -> None:
    """List built-in safe detection rules."""
    _print({"rules": _pipeline().detection_rules()})


@detection_app.command("run-once")
def detection_run_once(
    dataset: str = typer.Option("synthetic", "--dataset"),
    profile: str | None = typer.Option(None, "--profile"),
    policy_id: str | None = typer.Option(None, "--policy-id"),
    policy_version: str | None = typer.Option(None, "--policy-version"),
    model_id: str | None = typer.Option(None, "--model-id"),
    start: str | None = typer.Option(None, "--start"),
    end: str | None = typer.Option(None, "--end"),
    batch_size: int = typer.Option(256, "--batch-size", min=1, max=4096),
    max_windows: int | None = typer.Option(None, "--max-windows", min=1),
    rules_only: bool = typer.Option(False, "--rules-only"),
    dry_run: bool = typer.Option(False, "--dry-run"),
) -> None:
    """Run Stage 4 detection once over materialized feature windows."""
    try:
        _print(
            _pipeline().detection_run_once(
                dataset_kind=dataset,
                profile=profile,
                policy_id=policy_id,
                policy_version=policy_version,
                model_id=model_id,
                start=_parse_datetime(start),
                end=_parse_datetime(end),
                batch_size=batch_size,
                max_windows=max_windows,
                rules_only=rules_only,
                dry_run=dry_run,
            )
        )
    except ValueError as exc:
        typer.echo(str(exc), err=True)
        raise typer.Exit(code=2) from exc


@detection_app.command("backfill")
def detection_backfill(
    dataset: str = typer.Option("synthetic", "--dataset"),
    policy_id: str | None = typer.Option(None, "--policy-id"),
    policy_version: str | None = typer.Option(None, "--policy-version"),
    model_id: str | None = typer.Option(None, "--model-id"),
    start: str | None = typer.Option(None, "--start"),
    end: str | None = typer.Option(None, "--end"),
    dataset_id: str | None = typer.Option(None, "--dataset-id"),
    confirm: bool = typer.Option(False, "--confirm"),
    advance_watermark: bool = typer.Option(False, "--advance-watermark"),
    confirm_advance_watermark: bool = typer.Option(False, "--confirm-advance-watermark"),
) -> None:
    """Backfill Stage 4 detection over an explicit range or registered dataset."""
    try:
        _print(
            _pipeline().detection_backfill(
                dataset_kind=dataset,
                policy_id=policy_id,
                policy_version=policy_version,
                model_id=model_id,
                start=_parse_datetime(start),
                end=_parse_datetime(end),
                registered_dataset_id=dataset_id,
                confirm=confirm,
                advance_watermark=advance_watermark,
                confirm_advance_watermark=confirm_advance_watermark,
            )
        )
    except ValueError as exc:
        typer.echo(str(exc), err=True)
        raise typer.Exit(code=2) from exc


@detection_runs_app.command("list")
def detection_runs_list() -> None:
    """List Stage 4 detection runs."""
    _print({"detection_runs": _pipeline().detection_runs()})


@detection_runs_app.command("show")
def detection_runs_show(detection_run_id: str) -> None:
    """Show one Stage 4 detection run."""
    run = _pipeline().detection_run(detection_run_id)
    if run is None:
        typer.echo("detection run not found", err=True)
        raise typer.Exit(code=2)
    _print(run)


@detection_findings_app.command("list")
def detection_findings_list(
    status: str | None = typer.Option(None, "--status"),
    dataset: str | None = typer.Option(None, "--dataset"),
) -> None:
    """List privacy-safe Stage 4 findings."""
    _print({"findings": _pipeline().detection_findings(status=status, dataset_kind=dataset)})


@detection_findings_app.command("show")
def detection_findings_show(finding_id: str) -> None:
    """Show finding details, occurrences, and lifecycle history."""
    finding = _pipeline().detection_finding(finding_id)
    if finding is None:
        typer.echo("finding not found", err=True)
        raise typer.Exit(code=2)
    _print(finding)


def _transition_finding(finding_id: str, to_status: str, reason: str, confirm: bool) -> None:
    try:
        _print(
            _pipeline().detection_transition_finding(
                finding_id,
                to_status=to_status,
                reason=reason,
                confirm=confirm,
            )
        )
    except ValueError as exc:
        typer.echo(str(exc), err=True)
        raise typer.Exit(code=2) from exc


@detection_findings_app.command("acknowledge")
def detection_findings_acknowledge(
    finding_id: str,
    reason: str = typer.Option("manual acknowledge", "--reason"),
) -> None:
    """Acknowledge an open finding."""
    _transition_finding(finding_id, "acknowledged", reason, False)


@detection_findings_app.command("investigate")
def detection_findings_investigate(
    finding_id: str,
    reason: str = typer.Option("manual investigation", "--reason"),
) -> None:
    """Move a finding into investigating."""
    _transition_finding(finding_id, "investigating", reason, False)


@detection_findings_app.command("resolve")
def detection_findings_resolve(
    finding_id: str,
    reason: str = typer.Option("manual resolution", "--reason"),
    confirm: bool = typer.Option(False, "--confirm"),
) -> None:
    """Resolve a finding with explicit confirmation."""
    _transition_finding(finding_id, "resolved", reason, confirm)


@detection_findings_app.command("false-positive")
def detection_findings_false_positive(
    finding_id: str,
    reason: str = typer.Option("manual false positive", "--reason"),
    confirm: bool = typer.Option(False, "--confirm"),
) -> None:
    """Mark a finding false positive with explicit confirmation."""
    _transition_finding(finding_id, "false_positive", reason, confirm)


@detection_suppressions_app.command("list")
def detection_suppressions_list() -> None:
    """List exact, TTL-bound detection suppressions."""
    _print({"suppressions": _pipeline().detection_suppressions()})


@detection_suppressions_app.command("create")
def detection_suppressions_create(
    scope: str = typer.Option(..., "--scope"),
    reason: str = typer.Option(..., "--reason"),
    ttl_minutes: int = typer.Option(..., "--ttl-minutes", min=1),
    dataset: str | None = typer.Option(None, "--dataset"),
    profile: str | None = typer.Option(None, "--profile"),
    fingerprint: str | None = typer.Option(None, "--fingerprint"),
    signal_id: str | None = typer.Option(None, "--signal-id"),
) -> None:
    """Create an exact suppression; regex and arbitrary code are not supported."""
    try:
        _print(
            _pipeline().detection_create_suppression(
                scope=scope,
                reason=reason,
                ttl_minutes=ttl_minutes,
                dataset_kind=dataset,
                profile_key=profile,
                finding_fingerprint=fingerprint,
                signal_id=signal_id,
            )
        )
    except ValueError as exc:
        typer.echo(str(exc), err=True)
        raise typer.Exit(code=2) from exc


@detection_suppressions_app.command("revoke")
def detection_suppressions_revoke(
    suppression_id: str,
    confirm: bool = typer.Option(False, "--confirm"),
) -> None:
    """Revoke an active suppression."""
    try:
        _print(_pipeline().detection_revoke_suppression(suppression_id, confirm=confirm))
    except ValueError as exc:
        typer.echo(str(exc), err=True)
        raise typer.Exit(code=2) from exc


@detection_worker_app.command("status")
def detection_worker_status(dataset: str = typer.Option("synthetic", "--dataset")) -> None:
    """Show local detection worker lease state."""
    _print(_pipeline().detection_worker_status(dataset_kind=dataset))


@detection_worker_app.command("start")
def detection_worker_start(
    dataset: str = typer.Option("synthetic", "--dataset"),
    interval_seconds: int = typer.Option(60, "--interval-seconds", min=5),
    max_windows: int | None = typer.Option(256, "--max-windows", min=1),
) -> None:
    """Run the local worker in the foreground without installing an OS service."""
    try:
        _print(
            _pipeline().detection_worker_run_foreground(
                dataset_kind=dataset,
                max_windows=max_windows,
                interval_seconds=interval_seconds,
                single_cycle=False,
            )
        )
    except KeyboardInterrupt:
        _print(_pipeline().detection_worker_stop(dataset_kind=dataset, confirm=True))


@detection_worker_app.command("stop")
def detection_worker_stop(
    dataset: str = typer.Option("synthetic", "--dataset"),
    confirm: bool = typer.Option(False, "--confirm"),
) -> None:
    """Request local detection worker stop."""
    _print(_pipeline().detection_worker_stop(dataset_kind=dataset, confirm=confirm))


@detection_worker_app.command("run-foreground")
def detection_worker_run_foreground(
    dataset: str = typer.Option("synthetic", "--dataset"),
    max_windows: int | None = typer.Option(256, "--max-windows", min=1),
    interval_seconds: int = typer.Option(60, "--interval-seconds", min=5),
    single_cycle: bool = typer.Option(False, "--single-cycle"),
) -> None:
    """Run the local worker loop in the foreground."""
    try:
        _print(
            _pipeline().detection_worker_run_foreground(
                dataset_kind=dataset,
                max_windows=max_windows,
                interval_seconds=interval_seconds,
                single_cycle=single_cycle,
            )
        )
    except KeyboardInterrupt:
        _print(_pipeline().detection_worker_stop(dataset_kind=dataset, confirm=True))
    except ValueError as exc:
        typer.echo(str(exc), err=True)
        raise typer.Exit(code=2) from exc


@app.command("run-api")
def run_api(host: str = "127.0.0.1", port: int = 8000) -> None:
    """Run FastAPI development server."""
    uvicorn.run(fastapi_app, host=host, port=port)
