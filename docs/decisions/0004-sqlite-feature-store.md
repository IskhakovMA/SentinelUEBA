# ADR 0004: SQLite Feature Store

## Status

Accepted.

## Context

SentinelUEBA is local-first and currently runs as a modular monolith. Stage 2 needs
persistent feature windows, materialization state, quarantine records, quality summaries,
and dataset snapshot metadata without adding infrastructure.

## Decision

Use SQLite v4 tables for the feature store:

- `feature_windows`
- `feature_materialization_state`
- `data_quality_runs`
- `quarantined_events`
- `dataset_snapshots`

## Consequences

SQLite keeps Windows setup simple and CI portable. It is not a streaming framework; late
event handling is implemented by deterministic invalidation and rebuild of affected
window ranges.
