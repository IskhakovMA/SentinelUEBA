# ADR 0006: Cumulative Usable 24-Hour Coverage

## Status

Accepted.

## Context

Stage 1 reported cumulative collection duration, but duration alone does not prove that
training data is usable. Missing collectors, gaps, or empty telemetry can make a long
session unsuitable.

## Decision

Real training requires at least 24 cumulative hours of usable real coverage. Usable
coverage is counted from good feature windows in a single user+host profile with a
compatible feature schema. The UI and API still show strict continuous 24-hour validation
separately.

## Consequences

Users can accumulate usable coverage across sessions, but degraded or insufficient windows
do not silently satisfy the training gate.
