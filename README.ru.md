# SentinelUEBA

SentinelUEBA — local-first Windows-focused UEBA портфолио-проект. Stage 2 сохраняет synthetic demo и opt-in Windows telemetry из предыдущих стадий, затем добавляет validation, data quality, materialized feature windows, immutable Parquet dataset snapshots, retention controls, FastAPI, CLI и React-интерфейс.

[English version](README.md)

## Возможности

- Безопасная synthetic demo telemetry за 24-hour-equivalent период.
- Opt-in Windows collectors для процессов, сети, системных метрик и optional Security Event Log authentication metadata.
- SQLite с последовательными миграциями, индексами, защитой от дублей, collection sessions, collector observations и collector cursors.
- Payload validation, quarantine и ingestion metadata.
- Persistent 15-минутные UTC feature windows для пары user + host.
- Immutable Parquet dataset snapshots с manifest и SHA-256 verification.
- CPU-friendly PyTorch autoencoder с preprocessing и model metadata.
- Объяснения на основе per-feature reconstruction residual.
- Post-inference validation для всех пяти canonical synthetic demo-сценариев.
- Уровни риска: low, medium, high, critical.
- FastAPI endpoints и двуязычная EN/RU панель на React.

Аномалия означает статистическое отклонение от профиля. Это не доказательство атаки.

## Быстрый запуск

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

Обучение и snapshot-backed detection теперь используют verified dataset snapshots, а не произвольное текущее содержимое SQLite.
Подробнее: [data pipeline](docs/DATA_PIPELINE.md), [data quality](docs/DATA_QUALITY.md), [dataset snapshots](docs/DATASET_SNAPSHOTS.md).

## Ограничения Stage 2

Не реализованы Windows Service, Linux collectors, ETW, kernel driver, cloud backend, SIEM, alerts, packet capture, keylogging, clipboard, browser history, traffic payload inspection, Isolation Forest и ручная калибровка threshold.

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
