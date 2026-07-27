# Detection Policies

The default Stage 4 policy is `hybrid-policy-v1`.

Properties:

- immutable version and deterministic policy hash;
- default mode `hybrid`;
- quality gate accepts `good` windows by default;
- rules-only fallback is allowed when no verified champion exists;
- `model_only` requires a verified champion;
- fusion method is `hybrid-fusion-v1`;
- finding threshold is 55;
- risk thresholds are low 35, medium 55, high 75, and critical 90.

Policies are Pydantic-validated and cannot contain arbitrary user Python, SQL, shell
commands, or artifact paths.
