# SentinelUEBA

SentinelUEBA — local-first Windows-focused UEBA портфолио-проект. Stage 1 сохраняет synthetic demo из Stage 0 и добавляет opt-in сбор Windows-телеметрии, collection sessions, cumulative 24-hour progress, FastAPI, CLI и React-интерфейс.

[English version](README.md)

## Возможности

- Безопасная synthetic demo telemetry за 24-hour-equivalent период.
- Opt-in Windows collectors для процессов, сети, системных метрик и optional Security Event Log authentication metadata.
- SQLite с последовательными миграциями, индексами, защитой от дублей, collection sessions и collector cursors.
- 15-минутные окна признаков для пары user + host.
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

Real training разрешается только после 24 накопительных часов real non-synthetic telemetry и достаточного числа feature windows. Накопительный сбор считается отдельно от strict continuous 24-hour validation.

Подробнее: [Windows collection](docs/WINDOWS_COLLECTION.md).

Stage 1 сохраняет heartbeats collection session. После остановки приложения или компьютера stale session закрывается по последнему heartbeat, поэтому выключенное время не входит в collected duration.

## Ограничения Stage 1

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
