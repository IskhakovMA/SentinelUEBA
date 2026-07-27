# Data Quality

Stage 2 separates absence of telemetry from confirmed low activity.

Quality statuses:

- `good`: core telemetry is present and coverage is sufficient.
- `degraded`: partial telemetry is present, or recommended sources such as network are
  missing, but the window can still be inspected.
- `insufficient`: no collection heartbeat covers the window, or core process and system
  metrics are missing.

For real windows, process and system metrics are core sources. Network is recommended:
temporary absence makes a window `degraded`. Authentication is optional; unavailable or
permission-required Security Event Log access is reported but does not make a window
unusable by itself.

Coverage is derived from `collector_observations`. Each poll records session id,
collector id, observed timestamp, status, success flag, error class, configured interval,
returned event count, and saved event count. Successful zero-event polls still count as
coverage for collectors such as process and network because they prove the collector was
alive and observed no changes. Raw collection session duration is reported separately and
is not counted as per-window coverage by itself.

Usable real coverage is calculated from good 15-minute real windows. Real model training
requires 24 cumulative hours of usable real coverage in one user+host profile. This is not
the same as strict continuous 24-hour collection. The API and CLI report both cumulative
collection and strict continuous validation.

Rejected events are written to `quarantined_events` with a safe normalized event
representation, reason, collector/source, receipt timestamp, schema version, and error
class. The quarantine does not store fields removed by the normalizer.

The quality summary also reports received and accepted events, duplicate events, late
events split by policy, and collector observation counts. Readiness uses the same real
eligibility rules as training: one real profile, compatible feature schema, at least 96
good windows, 24 hours of usable good coverage, core process/system coverage, and no
synthetic windows mixed into the real dataset.

Use:

```bash
sentinelueba data-quality
sentinelueba quarantine summary
sentinelueba training-eligibility real
```
