# SentinelUEBA

SentinelUEBA — local-first Windows-focused UEBA портфолио-проект. Stage 4 сохраняет synthetic demo, opt-in Windows telemetry, validation-first ingestion, SQLite feature store, immutable snapshots и Stage 3 ML registry, затем добавляет privacy-safe detection engine с immutable policies, встроенными rules по feature windows, verified champion model signals, deterministic fusion, findings, suppressions, CLI/API controls, local worker lease и React Detection Center.

[English version](README.md)

## Возможности

- Безопасная synthetic demo telemetry за 24-hour-equivalent период.
- Opt-in Windows collectors для процессов, сети, системных метрик и optional Security Event Log authentication metadata.
- SQLite с последовательными миграциями, индексами, защитой от дублей, collection sessions, collector observations, dataset snapshots, model registry v8 и detection schema v9.
- Payload validation, quarantine и ingestion metadata до canonical normalization.
- Persistent 15-минутные UTC feature windows для пары user + host.
- Immutable Parquet dataset snapshots с manifest и SHA-256 verification.
- Leakage-safe train/calibration/test split из verified registered snapshots.
- CPU-friendly PyTorch Autoencoder v2 и scikit-learn Isolation Forest baseline.
- Calibration-only anomaly thresholding с higher-is-more-anomalous scores.
- Immutable model bundles с manifest, model card, SHA-256 checksums и SQLite registry rows.
- Lifecycle candidate, recommended, champion, retired, rejected и failed с явным promotion/rollback.
- Offline snapshot scoring, scored-window audit rows, compatibility checks и drift reports.
- Объяснения на основе per-feature reconstruction residual и context deviation.
- Post-inference validation для всех пяти canonical synthetic demo-сценариев.
- Stage 4 hybrid detection policy `hybrid-policy-v1` поверх feature windows и verified champion models.
- Immutable findings, occurrences, lifecycle history, exact TTL suppressions, idempotent evaluations и worker watermarks.
- Уровни риска: low, medium, high, critical.
- FastAPI endpoints и двуязычная EN/RU панель на React.

Аномалия или finding является triage-сигналом. Это не доказательство атаки.

## Быстрый запуск

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

Откройте `http://localhost:5173`.

## Windows Collection

```powershell
uv run sentinelueba capabilities
uv run sentinelueba collect --duration 300 --interval 5
uv run sentinelueba collector-status
uv run sentinelueba collection-sessions
uv run sentinelueba training-eligibility --dataset real
```

Real training разрешается только после 24 накопительных часов usable real coverage из good feature windows в одном user + host profile. Coverage считается по successful collector observations, а не по raw session duration. Накопительный сбор считается отдельно от strict continuous 24-hour validation.

Подробнее: [Windows collection](docs/WINDOWS_COLLECTION.md).

Stage 1 сохраняет heartbeats collection session. После остановки приложения или компьютера stale session закрывается по последнему heartbeat, поэтому выключенное время не входит в collected duration.

## Data Pipeline

```bash
uv run sentinelueba data-quality
uv run sentinelueba features status
uv run sentinelueba datasets list
uv run sentinelueba datasets verify <dataset-id>
uv run sentinelueba retention preview
uv run sentinelueba quarantine summary
```

Обучение, public snapshot verification, matrix loading, detection, scoring, evaluation и drift reports используют verified registered dataset snapshots, а не произвольное текущее содержимое SQLite.

Подробнее: [data pipeline](docs/DATA_PIPELINE.md), [data quality](docs/DATA_QUALITY.md), [dataset snapshots](docs/DATASET_SNAPSHOTS.md).

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

Synthetic seed 42 обучает Autoencoder v2 и Isolation Forest candidates из verified snapshot. Scenario labels используются только для held-out evaluation и recommendation, но не как feature columns и не как training input. Real datasets считаются unlabeled: система показывает flagged rates и limitations, а не выдуманные precision, recall, F1, ROC-AUC или PR-AUC.

Public model operations требуют finalized training runs и verified registered model rows. Во время training candidate bundles проходят private pending verification и становятся public только после одной SQLite transaction, которая переводит training run в `success` и заполняет `verified_at` для всех candidate models.

Подробнее: [ML pipeline](docs/ML_PIPELINE.md), [model registry](docs/MODEL_REGISTRY.md), [model evaluation](docs/MODEL_EVALUATION.md), [model cards](docs/MODEL_CARDS.md).

## Detection Engine

```bash
uv run sentinelueba detection status
uv run sentinelueba detection policies list
uv run sentinelueba detection rules list
uv run sentinelueba detection run-once --dataset synthetic
uv run sentinelueba detection backfill --dataset synthetic --start <iso> --end <iso> --confirm
uv run sentinelueba detection findings list
uv run sentinelueba detection worker run-foreground --dataset synthetic --max-windows 256
```

Stage 4 DetectionInput содержит только window id, dataset kind, pseudonymous profile key, границы окна, feature schema version, ordered feature values, quality и feature input hash. Raw payloads, raw users, hosts, executable paths, remote addresses и synthetic scenario labels не попадают в rule engine.

Подробнее: [detection engine](docs/DETECTION_ENGINE.md), [rules](docs/DETECTION_RULES.md), [policies](docs/DETECTION_POLICIES.md), [finding lifecycle](docs/FINDING_LIFECYCLE.md), [continuous detection](docs/CONTINUOUS_DETECTION.md).

## Ограничения Stage 4

Не реализованы Windows Service, MSI, autostart, Linux collectors, ETW, kernel driver, cloud backend, SIEM, alerts, packet capture, keylogging, clipboard, browser history, traffic payload inspection, live blocking, automated response, arbitrary user Python/SQL/shell rules, online learning, retraining, autopromotion, supervised security labels и production alerting.

## Разработка

```bash
uv sync --all-extras --dev
uv run ruff check .
uv run mypy backend/src
uv run pytest
pnpm --dir frontend lint
pnpm --dir frontend typecheck
pnpm --dir frontend build
```
