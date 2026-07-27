# SentinelUEBA Data Pipeline

Stage 2 added the reproducible local data pipeline that Stage 3 ML consumes:

```mermaid
flowchart LR
  A["Collectors / synthetic generator"] --> B["raw TelemetryEvent"]
  B --> C["original-key and payload validation"]
  C -->|accepted| D["canonical normalization"]
  D --> E["SQLite telemetry_events"]
  C -->|rejected| Q["safe quarantined_events"]
  E --> F["feature materialization"]
  F --> G["verified registered Parquet snapshot"]
  G --> H["training / snapshot-backed detection"]
  H --> I["registered model bundle"]
  I --> J["controlled offline scoring"]
```

The project remains a modular monolith. SQLite stores raw events, quarantine records, collection metadata, materialized feature windows, materialization state, quality runs, dataset snapshot registry rows, model registry rows, training runs, model evaluations, promotions, scoring runs, and scored windows. Generated databases, snapshots, models, logs, and local identities stay outside Git.

## Versions

- Event schema: `event-v1`
- Feature schema: `feature-windows-v2`
- Dataset manifest: `dataset-manifest-v1`
- Split plan: `split-plan-v1`
- Model bundle: `model-bundle-v1`
- SQLite schema: v7

## Materialization

Stage 2 uses deterministic 15-minute tumbling windows aligned to UTC. Windows are partitioned by `dataset_kind`, `user_id`, and `host_id`; profiles are never mixed. Materialization sorts events once, groups them by profile and window, and calculates the Stage 0 feature set deterministically.

SQLite schema v6 includes `collector_observations` and richer `feature_materialization_state` fields: the last ingestion watermark, stable event id tie-breaker, event-time watermark, composite observation watermark (`last_observation_at`, `last_observation_id`), and last successful run time. Re-runs with no new events or observations return zero processed, upserted, and deleted rows and do not update timestamps.

Normal incremental runs read new events by ingestion watermark and new observations by the `(observed_at, observation_id)` watermark, derive affected 15-minute windows, then load only events in the affected event range and observations whose coverage intervals intersect that range. Novelty features use a SQL baseline query for processes and remote endpoints before the affected window, so unchanged history is not loaded into Python on each run. Full rebuild remains the explicit path that reads all history.

The default late-event interval is 60 minutes. Late events inside that interval invalidate the affected window range; late events outside the interval are recorded for quality reporting and skipped by incremental materialization. A full rebuild includes all events and should match an equivalent incremental run for in-policy late data.

For real data, materialized windows are keyed from successful collector observations as well as events. A successful zero-event process or network poll can therefore produce a real window and counts as coverage. Session `started_at` to `stopped_at` is not treated as automatic coverage.

## Validation

Payload validation checks the original payload keys before canonical normalization. Unknown or forbidden fields are quarantined, and the safe quarantine representation omits those forbidden values. Only payloads whose keys match the event-type contract are then normalized into the canonical stored form. Canonicalization runs only after validation accepts the event.

Use:

```bash
sentinelueba features materialize --dataset synthetic
sentinelueba features rebuild --dataset synthetic
sentinelueba features status
```

## Dataset Snapshots

Training uses immutable Parquet snapshots under:

```text
data/datasets/<dataset-id>/
  features.parquet
  manifest.json
  checksums.sha256
```

Snapshots include only feature windows and ML metadata by default. Raw event payloads are not included. Creating new data produces a new dataset id; existing snapshots are not modified in place.

Snapshots are written through a temporary directory and atomically renamed after internal file verification. Public verification, matrix loading, training, detection, scoring, evaluation, and drift require both the dataset files and a matching SQLite `dataset_snapshots` registry row. Verification checks dataset id safety, `checksums.sha256`, manifest hash, Parquet hash, SQLite registry hash, manifest version, feature schema, feature order, required Parquet columns, row count, profile/kind consistency, sorted unique windows, and absence of NaN/Infinity feature values.

## Stage 3 Registry Consumers

Stage 3 does not train from arbitrary current SQLite feature windows after a snapshot is created. Model bundles store the source dataset id, dataset manifest SHA-256, feature schema, feature order, split id, threshold, metrics, and artifact hashes. Offline scoring checks dataset kind, profile, feature schema, feature order, model bundle checksums, and SQLite registry hashes before writing `scoring_runs` and `scored_windows`.

Schema initialization follows the normal v0-to-v7 migration chain. Fresh databases and historical v1/v2/v3/v4/v5/v6 fixtures migrate to v7. A database already at v7 is checked for required tables and columns; missing required schema raises an integrity error instead of rerunning old migrations as self-healing DDL.
