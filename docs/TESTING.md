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

Tests use synthetic data, temporary SQLite databases, and CPU execution only. The backend suite covers Stage 0-3 behavior, including Stage 3 ML regression tests. Windows CI also runs unit tests, PowerShell syntax checks, and short safe collector/ML smokes without requiring Security Log access.

Stage 1 tests cover Event Log fixture/live parser equivalence through mocks, cursor semantics, handle closure, heartbeat recovery, interruptible stop, PID reuse, migration paths from v1/v2/fresh databases, duplicate counter handling, model SHA-256 validation, and all five canonical demo scenarios.

Stage 2 tests cover real collector payload contracts, payload validation, quarantine, unknown-field rejection before normalization, deterministic UTC window alignment, user+host isolation, synthetic/real separation, idempotent no-op materialization, bounded incremental reads, `(observed_at, observation_id)` observation watermarking, coverage-interval overlap reads, incremental window updates, late-event policy reporting, full rebuild equivalence, observation-based real coverage, failed poll observations, stable zero-change collector polls, heartbeat-gap rejection, Parquet round-trip verification, manifest/checksum/registry tamper rejection, missing registry rejection for public verify/load/detect paths, unsafe dataset ids, Parquet content validation, row index/boundary checks, partial snapshot cleanup, snapshot-backed detection, shared readiness eligibility, real 24-hour usable coverage eligibility, retention preview/apply, API endpoints, and CLI smoke.

Stage 3 tests cover leakage-safe synthetic splits, train-only preprocessing, calibration thresholds that do not depend on test rows, deterministic Autoencoder v2 training and round-trip loading, finite loss validation, Isolation Forest deterministic scoring with safe `skops` artifacts, bundle checksum tamper rejection, unsafe model ids, SQLite schema v7 migrations, one-champion lifecycle behavior, explicit retirement and rollback, immutable scoring runs, real unlabeled evaluation, no real auto-promotion, drift reports, incompatible profile rejection, insufficient-data drift status, ML API smoke, and ML CLI smoke.

CI keeps `backend`, `frontend`, and `windows` jobs. Backend and Windows jobs also run short dataset and ML pipeline smokes that create a synthetic snapshot, train a lightweight candidate, verify the registered model bundle, and run controlled offline scoring. Windows additionally asserts safe collector smoke results: no quarantine rows, readable returned/saved counters, successful process and system observations, a network observation, and no false network coverage from failed polls.
