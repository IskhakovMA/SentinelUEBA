# Detection Rules

Stage 4 ships five built-in immutable rule versions:

- `rare-process-v1`
- `new-remote-spike-v1`
- `unusual-hour-activity-v1`
- `resource-pressure-v1`
- `authentication-failure-burst-v1`

Rules operate only on materialized numeric feature-window values. They do not inspect raw
payloads, executable paths, remote addresses, authentication identities, or synthetic
scenario labels. Each rule emits a typed signal with signal id, version, source type,
matched flag, strength from 0 to 100, safe summary, typed evidence, contributing feature
names, and config hash.

Rule strength is detection signal strength, not probability, confidence, or proof.
