# ADR 0009: Immutable Model Bundles

## Status

Accepted.

## Context

Stage 3 needs reproducible local models that can be verified without relying on mutable process state.

## Decision

Write each model to a new immutable bundle directory containing manifest, split, preprocessor, metrics, model card, checksums, and exactly one model artifact. Register the manifest and artifact hashes in SQLite.

## Consequences

Tampering with bundle files or registry hashes is detected before scoring, promotion, or display. New training creates new model ids instead of modifying existing bundles.
