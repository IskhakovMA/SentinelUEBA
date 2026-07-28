# SentinelUEBA

SentinelUEBA is a local-first Windows-focused UEBA portfolio project. Stage 6 keeps the Stage 0-5 telemetry, validation-first data pipeline, ML registry, detection engine, and Windows portable runtime, then turns the React interface into a unified local product for demos, manual testing, and daily triage.

[Русская версия](README.ru.md)

## Features

- Safe synthetic 24-hour-equivalent demo telemetry.
- Opt-in Windows collectors for process, network, system metrics, and optional Security Event Log authentication metadata.
- SQLite storage with sequential migrations, indexes, duplicate protection, collection sessions, collector observations, dataset snapshots, model registry v8, and detection schema v10.
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
- Stage 4 hybrid detection policy `hybrid-policy-v1` over feature windows and verified champion models.
- Immutable findings, occurrences, lifecycle history, exact TTL suppressions, idempotent SQL anti-join evaluations, exact profile/model isolation, and worker watermarks.
- Risk levels: low, medium, high, critical.
- FastAPI endpoints and a bilingual EN/RU React dashboard.
- Windows x64 portable Technical Preview package with `SentinelUEBA.exe`, `SentinelUEBALauncher.exe`, `SentinelUEBAService.exe`, embedded frontend assets, runtime roots outside the install directory, and SHA-256 release manifest verification.
- Product dashboard pages for Overview, Telemetry, Data Pipeline, ML Lab, Detection Center, Findings, and Runtime.
- Guided synthetic demo flow from data generation through findings lifecycle and suppression without using the CLI.

An anomaly or finding is a triage signal. It is not proof of malicious activity.

## Quick Start

```powershell
uv sync --all-extras --dev
uv run sentinelueba generate-demo --seed 42
uv run sentinelueba features materialize --dataset synthetic
uv run sentinelueba datasets create --kind synthetic
uv run sentinelueba train --seed 42
uv run sentinelueba detect
uv run sentinelueba ml status
uv run sentinelueba detection run-once --dataset synthetic
uv run sentinelueba detection findings list
uv run sentinelueba run-api
pnpm --dir frontend install
pnpm --dir frontend dev
```

Open `http://localhost:5173`, or launch `SentinelUEBALauncher.exe` from the Windows portable bundle.

For a 5-10 minute UI walkthrough, see [demo flow](docs/DEMO_FLOW.md). For page responsibilities and safety rules, see [dashboard](docs/DASHBOARD.md).

## Windows Portable

```powershell
SentinelUEBA.exe --version
SentinelUEBA.exe verify-installation
SentinelUEBA.exe host run --open-browser
SentinelUEBA.exe host doctor
SentinelUEBA.exe host stop --confirm
```

Portable builds are PyInstaller one-folder Windows x64 bundles. Runtime data is stored in `%LOCALAPPDATA%\SentinelUEBA` for desktop mode and `%PROGRAMDATA%\SentinelUEBA` for service mode, never in the installation directory. Unsigned PR builds are Technical Preview artifacts and should verify as `unsigned_verified`.

See [Windows portable](docs/WINDOWS_PORTABLE.md), [runtime supervisor](docs/RUNTIME_SUPERVISOR.md), [installation integrity](docs/INSTALLATION_INTEGRITY.md), and [Windows Service](docs/WINDOWS_SERVICE.md).

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

Model public operations require finalized training runs and verified registered model rows. During training, candidate bundles are checked with a private pending verifier and become public only when one SQLite transaction marks the training run successful and fills `verified_at` for every candidate model.

See [ML pipeline](docs/ML_PIPELINE.md), [model registry](docs/MODEL_REGISTRY.md), [model evaluation](docs/MODEL_EVALUATION.md), and [model cards](docs/MODEL_CARDS.md).

## Detection Engine

```bash
uv run sentinelueba detection status
uv run sentinelueba detection policies list
uv run sentinelueba detection rules list
uv run sentinelueba detection run-once --dataset synthetic
uv run sentinelueba detection run-once --dataset synthetic --dry-run
uv run sentinelueba detection backfill --dataset synthetic --policy-id <policy-id> --start <iso> --end <iso> --confirm
uv run sentinelueba detection backfill --policy-id <policy-id> --dataset-id <registered-dataset-id> --confirm
uv run sentinelueba detection findings list
uv run sentinelueba detection suppressions create --scope signal_for_profile --profile <profile-key> --signal-id <signal-id> --ttl-minutes 60 --reason "maintenance"
uv run sentinelueba detection worker run-foreground --dataset synthetic --max-windows 256
uv run sentinelueba detection worker run-foreground --dataset synthetic --max-windows 256 --single-cycle
```

Stage 4 detection inputs contain only window id, dataset kind, pseudonymous profile key, window bounds, feature schema version, ordered feature values, quality, and feature input hash. Raw payloads, raw users, hosts, executable paths, remote addresses, and synthetic scenario labels do not enter the rule engine. No-profile runs create exact per-profile child runs; verified model signals are scored only for the model's dataset/profile namespace. Dry-run executes the same decision path without writing detection rows, findings, watermarks, suppressions, or worker leases. Registered-snapshot backfill verifies the snapshot and proves current feature-window identity matches the snapshot rows before processing exactly those window ids.

See [detection engine](docs/DETECTION_ENGINE.md), [rules](docs/DETECTION_RULES.md), [policies](docs/DETECTION_POLICIES.md), [finding lifecycle](docs/FINDING_LIFECYCLE.md), and [continuous detection](docs/CONTINUOUS_DETECTION.md).

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
- `backend/src/sentinelueba/detection`: legacy anomaly summaries plus Stage 4 contracts, policies, rules, fusion, findings, suppressions, and process-managed worker lease logic.
- `backend/src/sentinelueba/api`: FastAPI app.
- `frontend`: React, TypeScript, Vite dashboard.
- `docs`: architecture, privacy, threat model, and development notes.

## Stage 6 Limits

No reports export, benchmarking, formal validation, alerts, email/Telegram/webhooks, SIEM export, cloud backend, remote access, auto-update, installer, new ML algorithms, new detection rules, automatic training, automatic response, live blocking, online learning, retraining, autopromotion, supervised security labels, or production alerting are implemented. The Windows Service is optional, manual-start, loopback-only, and runs from the portable package after explicit install. Generated databases, snapshots, model bundles, identity secrets, logs, and reports are excluded from Git.

## Development

```bash
uv sync --all-extras --dev
uv run ruff check .
uv run mypy backend/src
uv run pytest
pnpm --dir frontend lint
pnpm --dir frontend typecheck
pnpm --dir frontend test
pnpm --dir frontend dashboard:smoke
pnpm --dir frontend build
```

Python dependencies are managed with `uv`; frontend dependencies use `pnpm`.

## Roadmap

Stage 6 focuses on local product usability. Stage 7 has not started; live alerts, SIEM export, and cloud backends remain out of scope.
