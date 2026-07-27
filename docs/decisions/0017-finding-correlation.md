# 0017 Finding Correlation

Finding correlation uses `finding-fingerprint-v2` over safe values only.

Windows with the same fingerprint within 60 minutes attach immutable occurrences to the
same open finding. The fingerprint includes dataset kind, pseudonymous profile key,
primary signal, matched rule ids, policy id/version/hash, and the model family/version
namespace or rules-only sentinel so policy and model changes cannot merge unrelated
findings. Resolved and false-positive findings are not silently reopened; a new matching
finding points at the previous terminal finding through `related_previous_finding_id`.
