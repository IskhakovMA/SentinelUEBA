# ADR 0004: SQLite Feature Store

## Status

Accepted.

## Context

SentinelUEBA is local-first and currently runs as a modular monolith. Stage 2 needs
persistent feature windows, materialization state, quarantine records, quality summaries,
and dataset snapshot metadata without adding infrastructure.

## Decision

Use SQLite v6 tables for the feature store:

- `feature_windows`
- `feature_materialization_state`
- `collector_observations`
- `late_event_records`
- `duplicate_event_records`
- `data_quality_runs`
- `quarantined_events`
- `dataset_snapshots`

## Consequences

SQLite keeps Windows setup simple and CI portable. It is not a streaming framework; late
event handling is implemented by deterministic invalidation and rebuild of affected
window ranges. Real coverage is derived from collector observations so a quiet but
successfully polled host can still produce usable windows without inventing change
events. Incremental materialization reads observations with the composite
`observed_at + observation_id` watermark and selects affected observations by
coverage-interval overlap. Fresh databases and historical v1/v2/v3/v4/v5 databases
migrate to v6. Databases already at schema v6 are verified for required structure;
missing tables or columns are treated as integrity failures instead of triggering old
migrations again.
