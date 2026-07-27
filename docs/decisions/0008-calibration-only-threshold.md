# ADR 0008: Calibration-Only Threshold

## Status

Accepted.

## Context

Using test scores to choose a threshold would leak evaluation data and overstate performance.

## Decision

Fit preprocessing on train rows only, fit models on train rows only, and derive anomaly thresholds only from calibration scores using deterministic quantile calibration. Test rows are held out until evaluation.

## Consequences

Thresholds are reproducible and auditable. Test metrics remain a held-out estimate instead of a tuned objective.
