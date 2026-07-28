# Demo Flow

This is the intended 5-10 minute Stage 6 walkthrough.

## Start

Development:

```bash
uv run sentinelueba run-api
pnpm --dir frontend dev
```

Windows portable:

```powershell
SentinelUEBALauncher.exe
```

Open the local dashboard. Confirm Runtime shows version `0.6.0`, host readiness, and no config warning.

## Walkthrough

1. Open Overview.
2. Click Generate synthetic demo.
3. Click Materialize features.
4. Click Create dataset.
5. Click Train models.
6. Confirm Promote champion.
7. Click Run detection.
8. Open Findings.
9. Select a finding and review the summary, score, signals, occurrence history, and lifecycle history.
10. Move the finding to acknowledged, then investigating or resolved as needed.
11. Create a short TTL suppression for the demonstrated signal and dataset kind.
12. Revoke the suppression.
13. Open Runtime.
14. Run Verify installation and Run doctor.

## What To Explain

- Synthetic demo data uses safe demo identifiers.
- Feature windows are 15-minute UTC windows and are separated by synthetic/real dataset kind.
- Training uses verified registered snapshots; scenario labels are held-out evaluation metadata, not training features.
- Promotion is manual and confirmed; there is no automatic training or automatic promotion.
- Detection findings are triage records, not proof of malicious activity.
- Suppressions are audited TTL controls and can be revoked.
- Runtime state is safe: no control token, absolute paths, username, or hostname are shown.

## Expected Result

The user can complete collection/generation, feature materialization, dataset creation, model training, champion promotion, detection, finding lifecycle, suppression, and runtime verification from one local interface without CLI commands.
