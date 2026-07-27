# SentinelUEBA

SentinelUEBA is a local-first Windows-focused UEBA portfolio project. Stage 1 keeps the synthetic demo from Stage 0 and adds opt-in Windows telemetry collection, collection sessions, cumulative 24-hour progress, FastAPI, CLI, and a React interface.

[Русская версия](README.ru.md)

## Features

- Safe synthetic 24-hour-equivalent demo telemetry.
- Opt-in Windows collectors for process, network, system metrics, and optional Security Event Log authentication metadata.
- SQLite storage with sequential migrations, indexes, duplicate protection, collection sessions, and collector cursors.
- 15-minute feature windows for user + host behavior.
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

Real training is gated by 24 cumulative hours of real non-synthetic telemetry and enough feature windows. Cumulative collection is tracked separately from strict continuous 24-hour validation; the project does not claim continuous validation unless the longest session actually reaches 24 hours.

See [Windows collection](docs/WINDOWS_COLLECTION.md).

Stage 1 persists collection heartbeats. If the application or computer stops, recovery closes the stale session at the last heartbeat, so powered-off time is not counted as collected duration.

## Architecture

The repository is a full-stack monorepo with a modular monolith backend:

- `backend/src/sentinelueba/domain`: event and anomaly models.
- `backend/src/sentinelueba/telemetry`: synthetic telemetry generation.
- `backend/src/sentinelueba/collectors`: Windows collector contracts and psutil/Event Log collectors.
- `backend/src/sentinelueba/normalization`: event normalization.
- `backend/src/sentinelueba/storage`: SQLite persistence and migrations.
- `backend/src/sentinelueba/features`: feature windows.
- `backend/src/sentinelueba/ml`: PyTorch autoencoder training and inference.
- `backend/src/sentinelueba/detection`: scoring and risk classification.
- `backend/src/sentinelueba/api`: FastAPI app.
- `frontend`: React, TypeScript, Vite dashboard.
- `docs`: architecture, privacy, threat model, and development notes.

## Stage 1 Limits

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

Stage 2 should harden Windows collection UX, add richer model evaluation, and introduce an Isolation Forest baseline without replacing the autoencoder.
