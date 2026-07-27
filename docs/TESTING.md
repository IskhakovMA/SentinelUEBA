# Testing

Run all checks:

```bash
uv run ruff check .
uv run mypy backend/src
uv run pytest
pnpm --dir frontend lint
pnpm --dir frontend typecheck
pnpm --dir frontend build
```

Tests use synthetic data, temporary SQLite databases, and CPU execution only.
Windows CI also runs unit tests, PowerShell syntax checks, and a short safe collector smoke without requiring Security Log access.
