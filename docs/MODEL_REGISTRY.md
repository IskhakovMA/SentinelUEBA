# Model Registry

SQLite schema v7 stores model lifecycle and scoring audit metadata.

Core tables:

- `training_runs`: dataset id, manifest SHA-256, split id, effective config, seed, status, source commit, and safe failure details. A running row is created early under a DB-backed same-profile lock.
- `model_versions`: model id, family, version, dataset id, feature schema, split id, artifact path, manifest hash, artifact hash, lifecycle status, threshold, and `verified_at`.
- `model_evaluations`: latest held-out metrics for each registered model.
- `model_promotions`: promote, retire, and rollback audit entries.
- `scoring_runs`: offline scoring run metadata.
- `scored_windows`: immutable per-window score, threshold, risk, and explanation rows.

Lifecycle states are `candidate`, `recommended`, `champion`, `retired`, `rejected`, and `failed`. SQLite enforces at most one champion per dataset kind/profile. Allowed transitions are:

- `candidate -> recommended` through explicit recommend or synthetic recommendation policy.
- `candidate/recommended -> champion` through promote.
- `champion -> retired` through retire.
- `retired -> champion` only through rollback.
- `failed/rejected` models cannot be promoted.

Promotion, retirement, and rollback require explicit confirmation in the CLI/API wrappers and verify the bundle, source snapshot, registry/manifest contract, evaluation row, and compatibility before changing lifecycle state. Rollback writes `model_promotions.action = "rollback"` and retires the previous champion. Retirement history records the retired model as `previous_model_id` and an empty `new_model_id`; it is not represented as a self-transition.

The compatibility service is used by verify/load/promote/rollback/score/detect/drift/compare. It proves that the model is registered, the source snapshot is registered and verified, optional target snapshots are registered and verified, dataset kind/profile/schema/order match, and model/registry/source hashes agree.

Model ids are constrained to safe generated ids such as:

```text
autoencoder-20260727120000-abcdef12
isolation-forest-20260727120000-abcdef12
```

Unsafe ids and path traversal attempts are rejected before filesystem access.
