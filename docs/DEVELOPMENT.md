# Development

## Stage 5 Packaging

Development mode keeps the existing backend and Vite workflow:

```bash
uv run sentinelueba run-api
pnpm --dir frontend dev
```

Packaged mode is Windows-only and built with:

```powershell
.\scripts\package-windows.ps1
```

Do not commit `frontend/dist`, databases, snapshots, model bundles, logs, certificates, or local `.env` files. Build identity is injected through environment variables such as `SENTINELUEBA_BUILD_COMMIT` and `SENTINELUEBA_BUILD_TIMESTAMP_UTC`; the installed app does not run `git`.

Runtime supervisor commands are available in development for smoke testing:

```bash
uv run sentinelueba host doctor
uv run sentinelueba host run
uv run sentinelueba verify-installation
```

Use Python 3.12, `uv`, `pnpm`, and Node 22.

Backend:

```bash
uv sync --all-extras --dev
uv run sentinelueba init
```

Frontend:

```bash
pnpm --dir frontend install
pnpm --dir frontend dev
```

Windows collection smoke:

```powershell
uv run sentinelueba collect --duration 60 --interval 5
uv run sentinelueba collector-status
```

Stage 3 data and ML pipeline smoke:

```bash
uv run sentinelueba generate-demo
uv run sentinelueba features materialize --dataset synthetic
uv run sentinelueba datasets create --kind synthetic
uv run sentinelueba datasets verify <dataset-id>
uv run sentinelueba data-quality
uv run sentinelueba ml train --dataset synthetic --families autoencoder,isolation-forest --autoencoder-epochs 20 --if-n-estimators 32
uv run sentinelueba ml models list
uv run sentinelueba ml models verify <model-id>
uv run sentinelueba ml models compare <model-id> <other-model-id>
uv run sentinelueba ml score --dataset <dataset-id> --model <model-id> --batch-size 64
```

Stage 4 detection smoke:

```bash
uv run sentinelueba detection status
uv run sentinelueba detection policies list
uv run sentinelueba detection rules list
uv run sentinelueba detection run-once --dataset synthetic
uv run sentinelueba detection runs list
uv run sentinelueba detection findings list
uv run sentinelueba detection worker run-foreground --dataset synthetic --max-windows 256 --single-cycle
```

The worker commands do not install an OS service, autostart task, or daemon supervisor.
`worker start` is a foreground alias; API start uses an in-process manager with a stop
event. Use `--single-cycle` for bounded local smoke tests.

Generated SQLite databases, Parquet snapshots, manifests, checksums, model bundles, logs,
and local identity secrets must remain outside Git.
