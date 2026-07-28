# Privacy

## Stage 5 Runtime Privacy

Packaged runtime APIs do not expose absolute installation, home, CI workspace, database, model, or log paths. Runtime status files contain only PID, process creation identity, start time, port, mode, version, and state. The local control token is stored separately, removed on shutdown, not logged, and not returned by status, doctor, or build endpoints.

Logs are rotating UTF-8 structured files and avoid raw telemetry payloads, raw username/hostname values, authentication identities, remote addresses, executable paths, full model feature rows, environment dumps, control tokens, PFX passwords, and certificate secrets.

The Windows portable package has no cloud upload, crash upload, remote control plane, autoupdate agent, or external script execution.

SentinelUEBA is local-first. Real collection is opt-in, local-only, and Windows-only. The application does not send telemetry to external services.

User and host identifiers are pseudonymized by default using a local salt stored in the data directory. The salt is ignored by Git. Raw identity mode is explicit configuration only.

Repository rules:

- no real user events;
- no real usernames or hostnames;
- no trained models from personal telemetry;
- no secrets or tokens;
- no generated SQLite databases, logs, model bundles, snapshots, or reports;
- no identity secret.

Stage 1 does not collect command lines, file contents, active windows, browser history, clipboard contents, keystrokes, packet payloads, or traffic payloads.

Windows authentication collection stores Security Event Log metadata only for supported interactive logon/logoff events. It does not change Windows audit policy.

## Stage 2 Data Handling

Payload validation checks original payload keys before canonical normalization. Rejected
events are quarantined with a safe representation and rejection reason; unknown or
forbidden payload values are omitted from quarantine records. Dataset snapshots contain
materialized feature windows and ML metadata only; raw event payloads are not included by
default.

Retention defaults to 30 days for raw real events and quarantined events. Dataset snapshots
and model artifacts are not deleted automatically.

## Stage 3 Model Handling

Model bundles contain feature schema metadata, split metadata, preprocessor statistics,
metrics, model cards, hashes, and model artifacts. They do not include raw event payloads,
raw usernames, hostnames, paths, network addresses, browser history, clipboard contents,
keystrokes, or packet payloads. Real evaluation is labeled as unlabeled and does not claim
attack accuracy.

## Stage 4 Detection Handling

Stage 4 `DetectionInput` is a privacy-safe contract. It includes only a window id,
dataset kind, pseudonymous profile key, window bounds, feature schema version, ordered
feature values, quality, and feature input hash. The rule engine and finding evidence do
not receive raw telemetry payloads, raw usernames, hostnames, executable paths, remote
addresses, authentication identities, command lines, or synthetic scenario labels.

Findings, occurrences, suppressions, lifecycle reasons, run errors, and API responses use
sanitized summaries and allowlisted feature names. Free-text reasons are normalized and
limited to 500 characters. A finding is an analyst triage record, not proof of malicious
activity.
