# 0016 Detection Idempotency

Detection evaluations are unique by window id, feature input hash, policy hash, and model
identity sentinel.

Repeating the same run is a no-op. Changed feature values, policy hash, or champion model
identity produce a new evaluation. Worker watermarks use window start plus window id as
the tie-breaker.
