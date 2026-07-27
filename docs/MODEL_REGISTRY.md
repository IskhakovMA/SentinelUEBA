# Model Registry

SQLite schema v8 stores model lifecycle and scoring audit metadata.

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

Promotion, recommendation, retirement, and rollback require explicit confirmation in the CLI/API wrappers and verify the bundle, source snapshot, registry/manifest/training-run contract, evaluation row, and compatibility before changing lifecycle state. Rollback writes `model_promotions.action = "rollback"` and retires the previous champion. Retirement history records the retired model as `previous_model_id` and `new_model_id = NULL`; it is not represented as a self-transition.

The compatibility service is used by public verify/load/promote/recommend/retire/rollback/score/detect/drift/compare. It proves that the model is registered and finalized, the source snapshot is registered and verified, optional target snapshots are registered and verified, dataset kind/profile/schema/order match, model/registry/source hashes agree, and the linked training run is successful with `completed_at` populated. During training, pending registered candidates are checked only by a private verifier until the finalization transaction fills `verified_at`.

Model ids are constrained to safe generated ids such as:

```text
autoencoder-20260727120000-abcdef12
isolation-forest-20260727120000-abcdef12
```

Unsafe ids and path traversal attempts are rejected before filesystem access.
