from __future__ import annotations

import json
import time

import typer
import uvicorn

from sentinelueba.api.main import app as fastapi_app
from sentinelueba.config import get_settings
from sentinelueba.services.pipeline import DemoPipeline

app = typer.Typer(help="SentinelUEBA local-first Stage 0 demo CLI.")


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


@app.command("run-api")
def run_api(host: str = "127.0.0.1", port: int = 8000) -> None:
    """Run FastAPI development server."""
    uvicorn.run(fastapi_app, host=host, port=port)
