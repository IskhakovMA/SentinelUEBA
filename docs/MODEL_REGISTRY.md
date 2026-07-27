# Model Registry

SQLite schema v7 stores model lifecycle and scoring audit metadata.

Core tables:

- `training_runs`: dataset id, manifest SHA-256, split id, effective config, seed, status, source commit, and safe failure details.
- `model_versions`: model id, family, version, dataset id, feature schema, split id, artifact path, manifest hash, artifact hash, lifecycle status, and threshold.
- `model_evaluations`: latest held-out metrics for each registered model.
- `model_promotions`: promote, retire, and rollback audit entries.
- `scoring_runs`: offline scoring run metadata.
- `scored_windows`: immutable per-window score, threshold, risk, and explanation rows.

Lifecycle states are `candidate`, `recommended`, `champion`, `retired`, `rejected`, and `failed`. SQLite enforces at most one champion per dataset kind/profile. Promotion and rollback require explicit confirmation in the CLI/API wrappers and verify the bundle plus source snapshot before changing the champion.

Model ids are constrained to safe generated ids such as:

```text
autoencoder-20260727120000-abcdef12
isolation-forest-20260727120000-abcdef12
```

Unsafe ids and path traversal attempts are rejected before filesystem access.
