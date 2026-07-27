# Data Quality

Stage 2 separates absence of telemetry from confirmed low activity.

Quality statuses:

- `good`: core telemetry is present and coverage is sufficient.
- `degraded`: partial telemetry is present, or recommended sources such as network are
  missing, but the window can still be inspected.
- `insufficient`: no collection heartbeat covers the window, or core process and system
  metrics are missing.

For real windows, process and system metrics are core sources. Network is recommended:
temporary absence makes a window `degraded`. Authentication is optional and never makes a
window unusable by itself.

Usable real coverage is calculated from good 15-minute real windows. Real model training
requires 24 cumulative hours of usable real coverage in one user+host profile. This is not
the same as strict continuous 24-hour collection. The API and CLI report both cumulative
collection and strict continuous validation.

Rejected events are written to `quarantined_events` with a safe normalized event
representation, reason, collector/source, receipt timestamp, schema version, and error
class. The quarantine does not store fields removed by the normalizer.

Use:

```bash
sentinelueba data-quality
sentinelueba quarantine summary
sentinelueba training-eligibility real
```
