# Architecture

SentinelUEBA Stage 0 is a local modular monolith. The backend owns telemetry generation, normalization, storage, feature engineering, model training, inference, and detection. The frontend calls FastAPI endpoints and renders pipeline status plus anomaly results.

The primary identity boundary is `user_id + host_id`. Events use UTC timestamps, safe synthetic identifiers, a structured payload, `synthetic=true`, and a schema version.

Stage 0 uses 15-minute non-overlapping windows. This keeps the demo fast and gives enough density for process, network, metrics, and authentication features.

