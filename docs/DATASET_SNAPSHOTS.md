# Dataset Snapshots

Dataset snapshots make training reproducible. The autoencoder no longer trains directly
from arbitrary current SQLite contents. The flow is:

1. Materialize feature windows.
2. Create an immutable Parquet snapshot.
3. Verify `manifest.json`, `features.parquet`, `checksums.sha256`, and the SQLite registry row.
4. Train from the verified snapshot matrix.

`manifest.json` records dataset id, kind, created time, application version, event schema
versions observed in the selected source data, feature schema version, profile, range,
window size, quality filters, feature names, source event counts, coverage summary,
Parquet SHA-256, materialized quality counts, included quality counts, and manifest
version.

`checksums.sha256` includes `features.parquet` and `manifest.json`. Loading a damaged
manifest, unreadable Parquet file, or checksum mismatch fails with a clear error.

Snapshot creation writes to a temporary directory and atomically renames it only after the
files verify. Verification rejects unsafe dataset ids, path traversal, missing
manifest/Parquet/checksum files, manifest/checksum tampering, SQLite registry mismatches,
wrong manifest version or feature order, missing or reordered Parquet columns, row count
mismatches, row index gaps, manifest start/end boundary mismatches, profile/kind
mismatches, duplicate or unsorted windows, and NaN/Infinity feature values.

Commands:

```bash
sentinelueba datasets create --kind synthetic
sentinelueba datasets list
sentinelueba datasets show <dataset-id>
sentinelueba datasets verify <dataset-id>
```

Synthetic scenario metadata may appear in the manifest for demo evaluation, but scenario
labels are never feature columns.

Stage 3 model training stores the dataset id and manifest SHA-256 in `training_runs`,
`model_versions`, and the model bundle manifest. Later detection and offline scoring
reload and verify a registered snapshot before scoring rows, so raw SQLite changes after
training do not silently change the model input. Drift reports also require registered
snapshots and reject incompatible dataset kind, profile, or feature schema.
