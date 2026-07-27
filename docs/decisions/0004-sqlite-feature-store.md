# ADR 0004: SQLite Feature Store And Model Registry

## Status

Accepted.

## Context

SentinelUEBA is local-first and currently runs as a modular monolith. Stage 2 needed persistent feature windows, materialization state, quarantine records, quality summaries, and dataset snapshot metadata without adding infrastructure. Stage 3 needs durable model registry, evaluation, promotion, and offline scoring audit rows while keeping the same local deployment model. Stage 4 adds detection audit tables while staying on SQLite.

## Decision

Use SQLite as the local feature store, model registry, and detection audit store. Stage 2 feature-store tables remain:

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

The first Stage 4 detection migration adds:

- `detection_policies`
- `detection_runs`
- `detection_evaluations`
- `findings`
- `finding_occurrences`
- `finding_state_history`
- `detection_suppressions`
- `detection_watermarks`
- `detection_worker_leases`

Stage 4 schema v10 adds persisted feature-window `profile_key` and `feature_input_hash`
columns, `detection_policy_activations`, expanded run counters/status fields, worker
lease namespace columns, suppression audit fields on evaluations, and
`related_previous_finding_id` for `finding-fingerprint-v2` correlation.

## Consequences

SQLite keeps Windows setup simple and CI portable. It is not a streaming framework; late event handling is implemented by deterministic invalidation and rebuild of affected window ranges. Real coverage is derived from collector observations so a quiet but successfully polled host can still produce usable windows without inventing change events. Incremental materialization reads observations with the composite `observed_at + observation_id` watermark and selects affected observations by coverage-interval overlap.

The model registry can enforce one champion per dataset kind/profile, preserve model lifecycle transitions, and keep offline scoring auditable without introducing a second database. Schema v8 keeps `model_promotions.new_model_id` nullable so retirement history records a real `NULL` successor. The first Stage 4 detection migration adds detection policy, evaluation, finding, suppression, watermark, and worker lease audit rows. Schema v10 tightens Stage 4 isolation and auditability without adding another database. Fresh and historical databases migrate to v10. Databases already at schema v10 are verified for required structure; missing tables or columns are treated as integrity failures instead of triggering old migrations again.
