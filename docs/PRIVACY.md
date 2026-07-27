# Privacy

SentinelUEBA is local-first. Stage 1 real collection is opt-in, local-only, and Windows-only. The application does not send telemetry to external services.

User and host identifiers are pseudonymized by default using a local salt stored in the data directory. The salt is ignored by Git. Raw identity mode is explicit configuration only.

Repository rules:

- no real user events;
- no real usernames or hostnames;
- no trained models from personal telemetry;
- no secrets or tokens;
- no generated SQLite databases, logs, models, or reports;
- no identity secret.

Stage 1 does not collect command lines, file contents, active windows, browser history, clipboard contents, keystrokes, packet payloads, or traffic payloads.
