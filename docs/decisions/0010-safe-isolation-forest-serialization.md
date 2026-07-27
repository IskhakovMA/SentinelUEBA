# ADR 0010: Safe Isolation Forest Serialization

## Status

Accepted.

## Context

Pickle is unsafe for loading untrusted Python objects. Stage 3 needs a scikit-learn Isolation Forest baseline without adding raw pickle loading.

## Decision

Serialize Isolation Forest artifacts with `skops`. Verification checks untrusted types against the expected estimator set before loading.

## Consequences

The project gets a CPU-friendly baseline model while avoiding raw pickle artifact loading.
