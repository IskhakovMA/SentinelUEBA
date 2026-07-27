# Roadmap

## Stage 0

Synthetic local demo pipeline, PyTorch autoencoder, FastAPI, React, tests, CI, and privacy-first documentation.

## Stage 1

- Safe opt-in Windows collectors.
- Collection sessions and cumulative 24-hour progress.
- Reconstruction residual explanations.
- Real training eligibility gate.

## Stage 2

- Payload validation and quarantine.
- SQLite feature store with incremental 15-minute window materialization.
- Data quality summary and usable coverage eligibility.
- Immutable Parquet dataset snapshots with manifests and checksums.
- Retention preview/apply controls.

## Recommended Stage 3

- Add richer model evaluation without changing the local-first privacy stance.
- Add controlled inference workflows after dataset snapshot compatibility checks.
- Consider signed local artifact metadata.
