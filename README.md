# SentinelUEBA

SentinelUEBA is a local-first Windows-focused UEBA portfolio project. Stage 3 keeps the synthetic demo, opt-in Windows telemetry, validation-first ingestion, SQLite feature store, data quality, retention, and immutable Parquet snapshots from earlier stages, then adds a reproducible local ML pipeline with model registry, evaluation, promotion, rollback, offline scoring, FastAPI, CLI, and a React ML Lab.

[Русская версия](README.ru.md)

## Features

- Safe synthetic 24-hour-equivalent demo telemetry.
- Opt-in Windows collectors for process, network, system metrics, and optional Security Event Log authentication metadata.
- SQLite storage with sequential migrations, indexes, duplicate protection, collection sessions, collector observations, dataset snapshots, and model registry v7.
- Payload validation, quarantine, and ingestion metadata before canonical normalization.
- Persistent 15-minute UTC feature windows for user + host behavior.
- Immutable Parquet dataset snapshots with manifests and SHA-256 verification.
- Leakage-safe train/calibration/test split from verified registered snapshots.
- CPU-friendly PyTorch Autoencoder v2 and scikit-learn Isolation Forest baseline.
- Calibration-only anomaly thresholding with higher-is-more-anomalous scores.
- Immutable model bundles with manifests, model cards, SHA-256 checksums, and SQLite registry rows.
- Candidate, recommended, champion, retired, rejected, and failed lifecycle states with explicit promotion/rollback.
- Offline snapshot scoring, scored-window audit rows, compatibility checks, and drift reports.
- Per-feature reconstruction residual and context-deviation explanations.
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
uv run sentinelueba ml status
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

Real training is gated by 24 cumulative hours of usable real coverage from good feature windows in one user + host profile. Coverage comes from successful collector observations, not from raw session duration. Cumulative collection is tracked separately from strict continuous 24-hour validation; the project does not claim continuous validation unless the longest session actually reaches 24 hours.

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

Training, public snapshot verification, matrix loading, detection, scoring, evaluation, and drift reports use verified registered dataset snapshots instead of arbitrary current SQLite contents.

See [data pipeline](docs/DATA_PIPELINE.md), [data quality](docs/DATA_QUALITY.md), and [dataset snapshots](docs/DATASET_SNAPSHOTS.md).

## ML Pipeline

```bash
uv run sentinelueba ml train --dataset synthetic --seed 42 --autoencoder-epochs 20 --if-n-estimators 32
uv run sentinelueba ml models list
uv run sentinelueba ml models verify <model-id>
uv run sentinelueba ml models recommend <model-id> --confirm
uv run sentinelueba ml models promote <model-id> --confirm
uv run sentinelueba ml score --dataset <dataset-id> --model <model-id> --batch-size 64
uv run sentinelueba ml drift --model <model-id> --dataset <dataset-id>
```

Synthetic seed 42 trains Autoencoder v2 and Isolation Forest candidates from a verified snapshot. Scenario labels are used only for held-out evaluation and recommendation, never as feature columns or training input. Real datasets are unlabeled: the system reports flagged rates and limitations instead of fake precision, recall, F1, ROC-AUC, or PR-AUC.

See [ML pipeline](docs/ML_PIPELINE.md), [model registry](docs/MODEL_REGISTRY.md), [model evaluation](docs/MODEL_EVALUATION.md), and [model cards](docs/MODEL_CARDS.md).

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
- `backend/src/sentinelueba/ml`: Stage 3 splitting, preprocessing, Autoencoder v2, Isolation Forest, calibration, registry-backed model bundles, evaluation, scoring, and drift.
- `backend/src/sentinelueba/detection`: risk classification and legacy anomaly summaries.
- `backend/src/sentinelueba/api`: FastAPI app.
- `frontend`: React, TypeScript, Vite dashboard.
- `docs`: architecture, privacy, threat model, and development notes.

## Stage 3 Limits

No Windows Service, Linux collectors, ETW, kernel driver, cloud backend, SIEM integration, alerts, packet capture, keylogging, clipboard, browser history, traffic payload inspection, live blocking, automated response, online learning, supervised security labels, or production alerting are implemented. Generated databases, snapshots, model bundles, identity secrets, logs, and reports are excluded from Git.

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

Stage 4 can focus on packaging and operational hardening. Live alerts, Windows Service packaging, SIEM export, and cloud backends remain out of scope for Stage 3.
