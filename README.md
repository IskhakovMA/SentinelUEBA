# SentinelUEBA

SentinelUEBA is a local-first Windows-focused UEBA portfolio project. Stage 0 implements a complete demo slice: synthetic telemetry, normalization, SQLite storage, feature windows, a small PyTorch autoencoder, anomaly detection, FastAPI, and a React interface.

[Русская версия](README.ru.md)

## Features

- Safe synthetic 24-hour-equivalent telemetry only.
- Event categories: process, network, system metrics, and authentication.
- SQLite storage with schema initialization, indexes, and duplicate protection.
- 15-minute feature windows for user + host behavior.
- CPU-friendly PyTorch autoencoder with saved preprocessing parameters.
- Risk levels: low, medium, high, critical.
- FastAPI endpoints and a bilingual EN/RU React dashboard.

An anomaly is a statistical deviation from the learned profile. It is not proof of malicious activity.

## Quick Start

```powershell
.\scripts\setup.ps1
.\scripts\demo.ps1
.\.venv\Scripts\sentinelueba run-api
pnpm --dir frontend dev
```

Open `http://localhost:5173`.

## Demo Workflow

```bash
./scripts/setup.sh
./scripts/demo.sh
```

The demo generates synthetic events for an accelerated 24-hour-equivalent period. This is different from cumulative real collection and from strict continuous 24-hour validation; Stage 0 does not claim a real 24-hour continuous production run.

## Architecture

The repository is a full-stack monorepo with a modular monolith backend:

- `backend/src/sentinelueba/domain`: event and anomaly models.
- `backend/src/sentinelueba/telemetry`: synthetic telemetry generation.
- `backend/src/sentinelueba/normalization`: event normalization.
- `backend/src/sentinelueba/storage`: SQLite persistence.
- `backend/src/sentinelueba/features`: feature windows.
- `backend/src/sentinelueba/ml`: PyTorch autoencoder training and inference.
- `backend/src/sentinelueba/detection`: scoring and risk classification.
- `backend/src/sentinelueba/api`: FastAPI app.
- `frontend`: React, TypeScript, Vite dashboard.
- `docs`: architecture, privacy, threat model, and development notes.

## Stage 0 Limits

No real collectors, Windows Service, cloud backend, SIEM integration, alerts, packet capture, keylogging, clipboard, browser history, or traffic payload inspection are implemented. Generated databases, models, logs, and reports are excluded from Git.

## Development

```bash
ruff check .
mypy backend/src
pytest
pnpm --dir frontend lint
pnpm --dir frontend typecheck
pnpm --dir frontend build
```

Python dependencies are managed with `uv`; frontend dependencies use `pnpm`.

## Roadmap

Stage 1 should add safe Windows collector interfaces, harden configuration, add richer visual analysis, and introduce an Isolation Forest baseline without replacing the autoencoder.

