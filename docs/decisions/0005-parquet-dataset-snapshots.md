# ADR 0005: Parquet Dataset Snapshots

## Status

Accepted.

## Context

Training directly from current SQLite contents makes results hard to reproduce. Stage 2
requires immutable local datasets with manifest metadata and checksums.

## Decision

Use Parquet snapshots written with `pyarrow`, plus `manifest.json` and
`checksums.sha256`.

## Consequences

Parquet is portable across Windows and Linux and is efficient for feature matrices.
Snapshots are generated local artifacts and are excluded from Git and CI artifacts.
Snapshot verification is required before training.
