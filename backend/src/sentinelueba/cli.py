from __future__ import annotations

import json
import time

import typer
import uvicorn

from sentinelueba.api.main import app as fastapi_app
from sentinelueba.config import get_settings
from sentinelueba.services.pipeline import DemoPipeline

app = typer.Typer(help="SentinelUEBA local-first UEBA CLI.")
features_app = typer.Typer(help="Materialized feature store commands.")
datasets_app = typer.Typer(help="Immutable dataset snapshot commands.")
retention_app = typer.Typer(help="Local retention policy commands.")
quarantine_app = typer.Typer(help="Quarantine inspection commands.")
ml_app = typer.Typer(help="Stage 3 ML pipeline commands.")
ml_runs_app = typer.Typer(help="ML training run commands.")
ml_models_app = typer.Typer(help="ML model registry commands.")
ml_scoring_app = typer.Typer(help="Offline scoring run commands.")
app.add_typer(features_app, name="features")
app.add_typer(datasets_app, name="datasets")
app.add_typer(retention_app, name="retention")
app.add_typer(quarantine_app, name="quarantine")
app.add_typer(ml_app, name="ml")
ml_app.add_typer(ml_runs_app, name="runs")
ml_app.add_typer(ml_models_app, name="models")
ml_app.add_typer(ml_scoring_app, name="scoring-runs")


def _pipeline() -> DemoPipeline:
    return DemoPipeline(get_settings())


def _print(payload: object) -> None:
    typer.echo(json.dumps(payload, indent=2, default=str))


@app.command()
def init() -> None:
    """Initialize local SQLite schema and artifact directories."""
    _print(_pipeline().initialize())


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
) -> None:
    """Run controlled offline scoring against a registered snapshot."""
    try:
        _print(_pipeline().ml_score(dataset_id=dataset_id, model_id=model_id))
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


@app.command("run-api")
def run_api(host: str = "127.0.0.1", port: int = 8000) -> None:
    """Run FastAPI development server."""
    uvicorn.run(fastapi_app, host=host, port=port)
