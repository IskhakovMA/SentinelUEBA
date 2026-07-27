# Development

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

Generated SQLite databases, Parquet snapshots, manifests, checksums, model bundles, logs,
and local identity secrets must remain outside Git.
