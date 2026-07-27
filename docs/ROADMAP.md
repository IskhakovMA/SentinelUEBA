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

## Stage 3

- Leakage-safe ML split and calibration-only thresholds.
- Autoencoder v2 and Isolation Forest candidate training.
- SQLite model registry v8 and immutable model bundles.
- Model evaluation, model cards, promotion, rollback, scoring runs, and drift reports.
- ML CLI/API and React ML Lab.

## Recommended Stage 4

- Package the local app for easier Windows operation.
- Harden long-running process supervision.
- Consider signed local artifact metadata.
- Keep live alerts, SIEM export, and cloud backends out of scope until explicitly planned.
