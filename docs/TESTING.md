# Testing

Run all checks:

```bash
ruff check .
mypy backend/src
pytest
pnpm --dir frontend lint
pnpm --dir frontend typecheck
pnpm --dir frontend build
```

Tests use synthetic data, temporary SQLite databases, and CPU execution only.

