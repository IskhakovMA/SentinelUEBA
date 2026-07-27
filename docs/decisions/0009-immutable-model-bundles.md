# ADR 0009: Immutable Model Bundles

## Status

Accepted.

## Context

Stage 3 needs reproducible local models that can be verified without relying on mutable process state.

## Decision

Write each model to a new immutable bundle directory containing manifest, split, preprocessor, metrics, model card, checksums, and exactly one model artifact. `manifest.artifact_hashes` is the trust anchor for `split.json`, `preprocessor.json`, `metrics.json`, `model_card.md`, and the family artifact. `checksums.sha256` must match the same hashes, so rewriting checksums after tampering is not sufficient.

Creation writes a temporary directory, performs internal verification before final rename, atomically renames to the final generated model id directory, registers `model_versions` with `verified_at = NULL`, and runs private pending registered verification while the training run is still running. After every candidate bundle and evaluation row has been recorded, one SQLite transaction marks the training run successful, sets `completed_at`, and fills `verified_at` for all candidate models.

## Consequences

Tampering with bundle files, manifest hashes, checksums, registry hashes, split metadata, preprocessor contract, model input dimension, source snapshot files, training-run fields, or registry fields is detected before scoring, promotion, rollback, drift, compare, or display. New training creates new model ids instead of modifying existing bundles. Failed creation removes temp/final directories and registry/evaluation rows before finalization; lifecycle failures after finalization leave verified candidates intact.
