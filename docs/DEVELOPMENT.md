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

Stage 2 data pipeline smoke:

```bash
uv run sentinelueba generate-demo
uv run sentinelueba features materialize --dataset synthetic
uv run sentinelueba datasets create --kind synthetic
uv run sentinelueba datasets verify <dataset-id>
uv run sentinelueba data-quality
```

Generated SQLite databases, Parquet snapshots, manifests, checksums, models, logs, and
local identity secrets must remain outside Git.
