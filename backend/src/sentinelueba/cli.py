from __future__ import annotations

import json

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


@app.command("run-api")
def run_api(host: str = "127.0.0.1", port: int = 8000) -> None:
    """Run FastAPI development server."""
    uvicorn.run(fastapi_app, host=host, port=port)

