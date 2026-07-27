# ADR 0011: Model Lifecycle

## Status

Accepted.

## Context

Multiple candidate models can exist for the same profile, but detection needs one clear default model.

## Decision

Store lifecycle states in SQLite: candidate, recommended, champion, retired, rejected, and failed. Enforce one champion per dataset kind/profile. Promotion, recommendation, retirement, and rollback are explicit audited actions. Retirement history stores the retired model as `previous_model_id` and leaves `new_model_id` as `NULL`.

## Consequences

Operators can compare and roll back models locally without deleting artifacts or guessing which model detection will use. Public lifecycle actions require finalized verified model registry rows, and the React ML Lab requires a browser confirmation before sending the API confirmation flag.
