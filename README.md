# SentinelUEBA

SentinelUEBA is a local-first Windows-focused UEBA portfolio project. Stage 2 keeps the synthetic demo and opt-in Windows telemetry from earlier stages, then adds validation, data quality, materialized feature windows, immutable Parquet dataset snapshots, retention controls, FastAPI, CLI, and a React interface.

[Русская версия](README.ru.md)

## Features

- Safe synthetic 24-hour-equivalent demo telemetry.
- Opt-in Windows collectors for process, network, system metrics, and optional Security Event Log authentication metadata.
- SQLite storage with sequential migrations, indexes, duplicate protection, collection sessions, and collector cursors.
- Payload validation, quarantine, and ingestion metadata.
- Persistent 15-minute UTC feature windows for user + host behavior.
- Immutable Parquet dataset snapshots with manifests and SHA-256 verification.
- CPU-friendly PyTorch autoencoder with saved preprocessing and model metadata.
- Per-feature reconstruction residual explanations.
- Post-inference validation for all five canonical synthetic demo scenarios.
- Risk levels: low, medium, high, critical.
- FastAPI endpoints and a bilingual EN/RU React dashboard.

An anomaly is a statistical deviation from the learned profile. It is not proof of malicious activity.

## Quick Start

```powershell
uv sync --all-extras --dev
uv run sentinelueba generate-demo --seed 42
uv run sentinelueba features materialize --dataset synthetic
uv run sentinelueba datasets create --kind synthetic
uv run sentinelueba train --seed 42
uv run sentinelueba detect
uv run sentinelueba run-api
pnpm --dir frontend install
pnpm --dir frontend dev
```

Open `http://localhost:5173`.

## Windows Collection

```powershell
uv run sentinelueba capabilities
uv run sentinelueba collect --duration 300 --interval 5
uv run sentinelueba collector-status
uv run sentinelueba collection-sessions
uv run sentinelueba training-eligibility --dataset real
```

Real training is gated by 24 cumulative hours of usable real coverage from good feature windows in one user + host profile. Cumulative collection is tracked separately from strict continuous 24-hour validation; the project does not claim continuous validation unless the longest session actually reaches 24 hours.

See [Windows collection](docs/WINDOWS_COLLECTION.md).

Stage 1 persists collection heartbeats. If the application or computer stops, recovery closes the stale session at the last heartbeat, so powered-off time is not counted as collected duration.

## Data Pipeline

```bash
uv run sentinelueba data-quality
uv run sentinelueba features status
uv run sentinelueba datasets list
uv run sentinelueba datasets verify <dataset-id>
uv run sentinelueba retention preview
uv run sentinelueba quarantine summary
```

Training now uses verified dataset snapshots instead of arbitrary current SQLite contents.
See [data pipeline](docs/DATA_PIPELINE.md), [data quality](docs/DATA_QUALITY.md), and [dataset snapshots](docs/DATASET_SNAPSHOTS.md).

## Architecture

The repository is a full-stack monorepo with a modular monolith backend:

- `backend/src/sentinelueba/domain`: event and anomaly models.
- `backend/src/sentinelueba/telemetry`: synthetic telemetry generation.
- `backend/src/sentinelueba/collectors`: Windows collector contracts and psutil/Event Log collectors.
- `backend/src/sentinelueba/normalization`: event normalization.
- `backend/src/sentinelueba/storage`: SQLite persistence and migrations.
- `backend/src/sentinelueba/features`: feature windows and materialization.
- `backend/src/sentinelueba/datasets`: immutable Parquet snapshots.
- `backend/src/sentinelueba/validation`: event payload validation and quarantine support.
- `backend/src/sentinelueba/ml`: PyTorch autoencoder training and inference.
- `backend/src/sentinelueba/detection`: scoring and risk classification.
- `backend/src/sentinelueba/api`: FastAPI app.
- `frontend`: React, TypeScript, Vite dashboard.
- `docs`: architecture, privacy, threat model, and development notes.

## Stage 2 Limits

No Windows Service, Linux collectors, ETW, kernel driver, cloud backend, SIEM integration, alerts, packet capture, keylogging, clipboard, browser history, traffic payload inspection, Isolation Forest, or manual threshold calibration are implemented. Generated databases, models, identity secrets, logs, and reports are excluded from Git.

## Development

```bash
uv sync --all-extras --dev
uv run ruff check .
uv run mypy backend/src
uv run pytest
pnpm --dir frontend lint
pnpm --dir frontend typecheck
pnpm --dir frontend build
```

Python dependencies are managed with `uv`; frontend dependencies use `pnpm`.

## Roadmap

Stage 3 should focus on richer evaluation and controlled inference workflows. Isolation Forest, live alerts, Windows Service packaging, SIEM export, and cloud backends remain out of scope for Stage 2.
