# ADR 0004: SQLite Feature Store And Model Registry

## Status

Accepted.

## Context

SentinelUEBA is local-first and currently runs as a modular monolith. Stage 2 needed persistent feature windows, materialization state, quarantine records, quality summaries, and dataset snapshot metadata without adding infrastructure. Stage 3 needs durable model registry, evaluation, promotion, and offline scoring audit rows while keeping the same local deployment model.

## Decision

Use SQLite v7 as the local feature store and model registry. Stage 2 feature-store tables remain:

- `feature_windows`
- `feature_materialization_state`
- `collector_observations`
- `late_event_records`
- `duplicate_event_records`
- `data_quality_runs`
- `quarantined_events`
- `dataset_snapshots`

Stage 3 adds:

- `training_runs`
- `model_versions`
- `model_evaluations`
- `model_promotions`
- `scoring_runs`
- `scored_windows`

## Consequences

SQLite keeps Windows setup simple and CI portable. It is not a streaming framework; late event handling is implemented by deterministic invalidation and rebuild of affected window ranges. Real coverage is derived from collector observations so a quiet but successfully polled host can still produce usable windows without inventing change events. Incremental materialization reads observations with the composite `observed_at + observation_id` watermark and selects affected observations by coverage-interval overlap.

The model registry can enforce one champion per dataset kind/profile, preserve model lifecycle transitions, and keep offline scoring auditable without introducing a second database. Fresh databases and historical v1/v2/v3/v4/v5/v6 databases migrate to v7. Databases already at schema v7 are verified for required structure; missing tables or columns are treated as integrity failures instead of triggering old migrations again.
