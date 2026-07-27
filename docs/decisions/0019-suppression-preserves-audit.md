# 0019 Suppression Preserves Audit

Suppressions are exact and TTL-bound.

Supported scopes are finding fingerprint, signal for profile, and signal for dataset
kind. Suppression does not delete evidence; it preserves evaluations and audit rows while
preventing new active security findings until expiry or revocation.
