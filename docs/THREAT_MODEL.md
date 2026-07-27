# Threat Model

Stage 1 detects statistical anomalies in synthetic or explicitly collected local Windows behavior windows. It does not classify malware, attribute attacks, inspect packet payloads, read file contents, record keystrokes, inspect clipboard data, or collect browser history.

The main risks are false positives, misunderstood explanations, missed short-lived process events due to polling, Security Log permission confusion, and accidental inclusion of private artifacts. The implementation mitigates them with opt-in collection, pseudonymous identity, honest explanations, `.gitignore`, and documentation.

## Stage 2 Data Integrity Risks

Stage 2 mitigates accidental training drift by requiring immutable dataset snapshots with
manifest and SHA-256 verification. Damaged manifests, corrupted Parquet files, and
incompatible feature schemas are rejected before training or loading. Quarantine prevents
malformed events from stopping collection or silently entering feature windows.
