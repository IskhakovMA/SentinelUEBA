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

Correlation uses `finding-fingerprint-v2` over safe values only: dataset kind,
pseudonymous profile key, primary signal id, matched rule ids, policy id/version/hash,
and the model family/version namespace or the rules-only sentinel. Matching windows whose
coverage interval intersects the 60-minute correlation window attach to the same open
finding. Resolved and false-positive findings are not silently reopened; a later matching
finding records `related_previous_finding_id`.

Occurrences are immutable audit rows. Suppression prevents new security findings while
preserving detection evaluations and audit evidence.
