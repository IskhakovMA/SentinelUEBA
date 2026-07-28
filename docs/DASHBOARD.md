# Dashboard

Stage 6 turns SentinelUEBA into a single local product interface. The dashboard does not change Stage 0-5 backend, ML, or detection semantics; it exposes them through safe same-origin API calls.

## Pages

- Overview: host readiness, events, feature windows, datasets, registered models, champion, open/high findings, collection and detection worker state, real-data readiness, latest actions, and the guided first-run flow.
- Telemetry: collector capabilities, collection status, progress, active/recent sessions, safe event summary, and ordinary/admin mode limitations. Collection controls are disabled in service mode.
- Data Pipeline: data quality, quarantine, feature schema, feature windows, synthetic/real snapshots, verification, training eligibility, retention preview, and confirmed retention apply.
- ML Lab: training eligibility, manual candidate training, Autoencoder and Isolation Forest candidates, metrics, registry, champion, promotion, rollback, scoring, drift, and safe reasons when an operation is blocked.
- Detection Center: active policy, policy mode, rules, model-signal availability, run-once, dry-run, exact snapshot backfill, worker controls, evaluated windows, finding/suppressed/no-op counts, and fusion explanation.
- Findings: filtered list, detail card, numeric evidence, rule/model signals, policy/model identity, occurrence history, lifecycle history, and suppression create/revoke.
- Runtime: version, build identity, packaged/development mode, signed state, installation verification, doctor state, host state, runtime mode, SQLite schema version, frontend hashes, config warning, safe log guidance, and desktop-only exit.

## Safety Rules

- The control token is kept in process memory only.
- The token is not rendered, stored in `localStorage`, logged, or put into URLs.
- A mutating 403 triggers one bootstrap refresh and one retry, not an infinite loop.
- Raw payloads, usernames, hostnames, absolute paths, executable paths, and remote addresses are not displayed.
- Lifecycle, suppression, retention, worker stop, backfill, and shutdown actions require confirmation before `confirm=true` reaches the API.

## Scope Boundaries

Stage 6 does not add reports export, alert delivery, SIEM export, cloud, remote access, auto-update, installer behavior, new ML algorithms, new detection rules, automatic training, automatic promotion, or automatic response.
