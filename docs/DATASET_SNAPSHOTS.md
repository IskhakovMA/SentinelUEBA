# Dataset Snapshots

Dataset snapshots make training reproducible. The autoencoder no longer trains directly
from arbitrary current SQLite contents. The flow is:

1. Materialize feature windows.
2. Create an immutable Parquet snapshot.
3. Verify `manifest.json` and `features.parquet` checksums.
4. Train from the verified snapshot matrix.

`manifest.json` records dataset id, kind, created time, application version, event schema
versions, feature schema version, profile, range, window size, quality filters, feature
names, event counts, coverage summary, Parquet SHA-256, and manifest version.

`checksums.sha256` includes `features.parquet` and `manifest.json`. Loading a damaged
manifest, unreadable Parquet file, or checksum mismatch fails with a clear error.

Commands:

```bash
sentinelueba datasets create --kind synthetic
sentinelueba datasets list
sentinelueba datasets show <dataset-id>
sentinelueba datasets verify <dataset-id>
```

Synthetic scenario metadata may appear in the manifest for demo evaluation, but scenario
labels are never feature columns.
