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
