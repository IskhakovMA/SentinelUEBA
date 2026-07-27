# ADR 0011: Model Lifecycle

## Status

Accepted.

## Context

Multiple candidate models can exist for the same profile, but detection needs one clear default model.

## Decision

Store lifecycle states in SQLite: candidate, recommended, champion, retired, rejected, and failed. Enforce one champion per dataset kind/profile. Promotion, retirement, and rollback are explicit audited actions.

## Consequences

Operators can compare and roll back models locally without deleting artifacts or guessing which model detection will use.
