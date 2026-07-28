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

## Stage 4

- Immutable `hybrid-policy-v1` detection policy with deterministic policy hash.
- Built-in safe feature-window rules and verified champion model signals.
- Deterministic `hybrid-fusion-v1` scoring, risk levels, findings, occurrences, lifecycle history, and exact TTL suppressions.
- SQLite schema v10 detection tables, SQL anti-join idempotent evaluations, composite worker watermarks, and local worker lease.
- Detection CLI/API and React Detection Center.

## Stage 5

- Windows x64 PyInstaller one-folder portable ZIP.
- Embedded production React frontend served by FastAPI on the same loopback origin.
- Runtime supervisor with single-instance protection, safe status metadata, graceful shutdown, and rotating logs.
- Local control-token contract for mutating browser/API actions.
- Runtime roots outside the installation directory for desktop and optional Windows Service mode.
- Build manifest, SHA-256 installation verification, optional SignTool integration, and package smoke CI.

## Future Scope

Installer signing, MSI/MSIX, auto-update, alerts, SIEM export, cloud backends, response actions, ETW/kernel collection, online learning, automatic retraining, and automatic model promotion remain out of scope until explicitly planned.
