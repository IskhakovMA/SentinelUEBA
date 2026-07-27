# ADR 0005: Parquet Dataset Snapshots

## Status

Accepted.

## Context

Training directly from current SQLite contents makes results hard to reproduce. Stage 2
requires immutable local datasets with manifest metadata and checksums.

## Decision

Use Parquet snapshots written with `pyarrow`, plus `manifest.json`, `checksums.sha256`,
and a SQLite registry row containing the manifest and file hashes.

## Consequences

Parquet is portable across Windows and Linux and is efficient for feature matrices.
Snapshots are generated local artifacts and are excluded from Git and CI artifacts.
Snapshot verification is required before training and snapshot-backed detection. The
verification path rejects checksum, manifest, registry, path safety, schema/order, row
count, row index, manifest boundary, profile/kind, ordering, duplicate window, and
NaN/Infinity failures before rows are used by ML code.
