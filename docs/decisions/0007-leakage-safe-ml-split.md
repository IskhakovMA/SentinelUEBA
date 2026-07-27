# ADR 0007: Leakage-Safe ML Split

## Status

Accepted.

## Context

Stage 3 needs reproducible evaluation without leaking synthetic scenario information into training or threshold calibration.

## Decision

Use chronological splits recorded in `split.json`. Synthetic snapshots split at the first scenario window: prior normal windows are train/calibration, and every scenario window is test only. Real snapshots use chronological 70/15/15 over good windows only.

## Consequences

Synthetic metrics can evaluate scenario recall without using labels during training. Real data remains unlabeled and cannot produce supervised accuracy claims.
