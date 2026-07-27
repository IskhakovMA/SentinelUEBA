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

The quality summary reports `received_events = accepted_events + duplicate_events +
quarantined_events`, plus accepted, duplicate, quarantined, late-within-policy,
late-outside-policy, and collector observation counts separately. Window quality is split
by `synthetic` and `real` so demo quality does not hide real collection gaps.

Readiness uses the same shared eligibility service as training: one real profile,
compatible feature schema, at least 96 good windows, 24 hours of usable good coverage,
cumulative duration, core process/system coverage, no synthetic windows mixed into the
real dataset, and cumulative duration greater than or equal to usable coverage.

Use:

```bash
sentinelueba data-quality
sentinelueba quarantine summary
sentinelueba training-eligibility real
```
