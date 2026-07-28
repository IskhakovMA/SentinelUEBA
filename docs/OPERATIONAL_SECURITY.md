# Operational Security

Stage 5 keeps SentinelUEBA local-first:

- no cloud control plane;
- no telemetry upload;
- no crash upload;
- no auto-update agent;
- no LAN listener;
- no Windows Firewall modification;
- no arbitrary script execution;
- no process or network blocking response.

Packaged host mode binds only to `127.0.0.1`. Mutating browser/API requests require
`X-SentinelUEBA-Control-Token`. The token is generated per host start, delivered only through the
same-origin bootstrap contract, and is not returned by status, doctor, or build endpoints.

The production host validates Host and Origin headers. Development keeps the existing Vite proxy
workflow.

Structured rotating logs redact tokens and runtime locations and avoid raw telemetry payloads,
raw identities, model feature rows, environment dumps, and certificate secrets.
