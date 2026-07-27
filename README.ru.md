# SentinelUEBA

SentinelUEBA — local-first Windows-focused UEBA портфолио-проект. Stage 0 реализует полный demo-срез: синтетическая телеметрия, нормализация, SQLite, временные признаки, небольшой PyTorch autoencoder, обнаружение аномалий, FastAPI и React-интерфейс.

[English version](README.md)

## Возможности

- Только безопасная синтетическая телеметрия за 24-hour-equivalent период.
- Категории событий: process, network, system_metrics, authentication.
- SQLite с созданием схемы, индексами и защитой от дублей.
- 15-минутные окна признаков для пары user + host.
- CPU-friendly PyTorch autoencoder с сохранением preprocessing parameters.
- Уровни риска: low, medium, high, critical.
- FastAPI endpoints и двуязычная EN/RU панель на React.

Аномалия означает статистическое отклонение от профиля. Это не доказательство атаки.

## Быстрый запуск

```powershell
.\scripts\setup.ps1
.\scripts\demo.ps1
.\.venv\Scripts\sentinelueba run-api
pnpm --dir frontend dev
```

Откройте `http://localhost:5173`.

## Demo Workflow

```bash
./scripts/setup.sh
./scripts/demo.sh
```

Demo генерирует ускоренный синтетический 24-hour-equivalent dataset. Это отличается от накопительного реального сбора и от strict continuous 24-hour validation. Stage 0 не утверждает, что проект прошёл реальное непрерывное 24-часовое тестирование.

## Ограничения Stage 0

Не реализованы реальные collectors Windows Event Log, процессы и сеть, Windows Service, Linux collectors, cloud backend, SIEM, alerts, packet capture, keylogging, clipboard, browser history и traffic payload inspection.

## Разработка

```bash
ruff check .
mypy backend/src
pytest
pnpm --dir frontend lint
pnpm --dir frontend typecheck
pnpm --dir frontend build
```

Python зависимости управляются через `uv`, frontend — через `pnpm`.

