# Finding Lifecycle

Findings are analyst triage records. They are not proof of malicious activity.

Statuses:

- `open`
- `acknowledged`
- `investigating`
- `resolved`
- `false_positive`
- `suppressed`

Destructive terminal states require explicit confirmation. Every transition writes
`finding_state_history` with a sanitized reason capped at 500 characters.

Correlation uses `finding-fingerprint-v1` over safe values only: dataset kind,
pseudonymous profile key, primary signal id, and matched signal ids. Matching windows
within 60 minutes correlate to the same open finding. Resolved and false-positive
findings are not silently reopened.

Occurrences are immutable audit rows. Suppression prevents new security findings while
preserving detection evaluations and audit evidence.
