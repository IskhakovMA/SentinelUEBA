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

Tests use synthetic data, temporary SQLite databases, and CPU execution only. The current
backend suite has 86 tests. Windows CI also runs unit tests, PowerShell syntax checks, and
a short safe collector smoke without requiring Security Log access.

Stage 1 tests cover Event Log fixture/live parser equivalence through mocks, cursor semantics, handle closure, heartbeat recovery, interruptible stop, PID reuse, migration paths from v1/v2/fresh databases, duplicate counter handling, model SHA-256 validation, and all five canonical demo scenarios.

Stage 2 tests cover real collector payload contracts, payload validation, quarantine,
unknown-field rejection before normalization, ingestion metadata migration from
historical SQLite v1/v2/v3/v4/v5 fixtures to v6, repeated v6 initialization without
rerunning migrations, schema integrity errors for damaged v6 databases, deterministic UTC
window alignment, user+host isolation, synthetic/real separation, idempotent no-op
materialization, bounded incremental reads, `(observed_at, observation_id)` observation
watermarking, coverage-interval overlap reads, incremental window updates, late-event
policy reporting, full rebuild equivalence, observation-based real coverage, failed poll
observations, stable zero-change collector polls, heartbeat-gap rejection, Parquet
round-trip verification, manifest/checksum/registry tamper rejection, missing registry
rejection for public verify/load/detect paths, unsafe dataset ids, Parquet content
validation, row index/boundary checks, partial snapshot cleanup, snapshot-backed
detection, shared readiness eligibility, real 24-hour usable coverage eligibility,
retention preview/apply, API endpoints, and CLI smoke.

CI keeps `backend`, `frontend`, and `windows` jobs. Backend and Windows jobs also run a
short dataset pipeline smoke that creates and verifies a synthetic Parquet snapshot.
Windows additionally asserts safe collector smoke results: no quarantine rows, readable
returned/saved counters, successful process and system observations, a network
observation, and no false network coverage from failed polls.
