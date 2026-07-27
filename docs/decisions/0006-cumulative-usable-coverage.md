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
compatible feature schema, core process coverage, and core system metrics coverage.
Feature window quality is derived from successful collector observations rather than raw
event counts or session start/stop duration. The UI and API still show strict continuous
24-hour validation separately.

## Consequences

Users can accumulate usable coverage across sessions, and a stable host with successful
zero-change polls can still be eligible. Degraded windows, insufficient windows, two-hour
observation gaps, synthetic data, and mixed profiles do not silently satisfy the training
gate.
