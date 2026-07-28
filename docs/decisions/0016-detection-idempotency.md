# 0016 Detection Idempotency

Detection evaluations are unique by window id, feature input hash, policy hash, and model
identity sentinel.

Pending windows are selected with a SQLite anti-join against prior evaluations, so the
engine does not full-scan Python-side history to decide what is new. Changed feature
values, policy hash, or champion model identity produce a new evaluation. Worker
watermarks use window start plus window id as the tie-breaker and optimization/audit
state, not as the source of correctness.
