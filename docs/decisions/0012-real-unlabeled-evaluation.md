# ADR 0012: Real Unlabeled Evaluation

## Status

Accepted.

## Context

Real endpoint telemetry in this project has no ground-truth attack labels.

## Decision

Report real evaluation as unlabeled. Provide flagged rates, score percentiles, timing, drift signals, and limitations. Do not report supervised metrics for real data.

## Consequences

The project avoids false accuracy claims and keeps the UI honest about what local unsupervised anomaly detection can and cannot prove.
