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

Stage 1 tests cover Event Log fixture/live parser equivalence through mocks, cursor semantics, handle closure, heartbeat recovery, interruptible stop, PID reuse, migration paths from v1/v2/fresh databases, duplicate counter handling, model SHA-256 validation, and all five canonical demo scenarios.

Stage 2 tests cover payload validation, quarantine, ingestion metadata migration,
deterministic UTC window alignment, user+host isolation, synthetic/real separation,
incremental materialization, late-event recomputation, full rebuild equivalence, Parquet
round-trip verification, checksum mismatch, damaged manifest handling, real 24-hour usable
coverage eligibility, retention preview/apply, API endpoints, and CLI smoke.

CI keeps `backend`, `frontend`, and `windows` jobs. Backend and Windows jobs also run a
short dataset pipeline smoke that creates and verifies a synthetic Parquet snapshot.
