# Threat Model

SentinelUEBA detects statistical anomalies in synthetic or explicitly collected local Windows behavior windows. It does not classify malware, attribute attacks, inspect packet payloads, read file contents, record keystrokes, inspect clipboard data, or collect browser history.

The main risks are false positives, misunderstood explanations, missed short-lived process events due to polling, Security Log permission confusion, and accidental inclusion of private artifacts. The implementation mitigates them with opt-in collection, pseudonymous identity, honest explanations, `.gitignore`, and documentation.

## Stage 2 Data Integrity Risks

Stage 2 mitigates accidental training drift by requiring immutable dataset snapshots with
manifest and SHA-256 verification. Damaged manifests, corrupted Parquet files, and
incompatible feature schemas are rejected before training or loading. Quarantine prevents
malformed events from stopping collection or silently entering feature windows.

## Stage 3 ML Risks

Stage 3 mitigates model tampering and accidental scoring drift with immutable model
bundles, SQLite registry hashes, verified snapshot loading, feature order checks, explicit
promotion/rollback, and safe `skops` loading for Isolation Forest artifacts. Remaining
risks include false positives, false negatives, synthetic-demo overfitting, unlabeled real
data, and explanations being mistaken for proof. The UI, API, CLI, docs, and model cards
state that an anomaly is not proof of malicious activity.

## Stage 4 Detection Risks

Stage 4 mitigates detection-engine risks with immutable policies, Pydantic-validated
contracts, built-in allowlisted rules, deterministic model-strength normalization,
deterministic fusion, idempotent evaluations, exact suppressions with TTL and revocation,
and SQLite lifecycle history. Rules cannot execute arbitrary Python, SQL, shell commands,
regular expressions, or user-provided code.

Remaining risks include false positives, false negatives, overfitting to synthetic
scenarios, suppressions hiding useful triage records until expiry, stale workers, and
analysts misunderstanding a finding as confirmed compromise. The CLI, API, frontend, and
docs state that findings are triage records only.
