# Development

Use Python 3.12, `uv`, `pnpm`, and Node 22.

Backend:

```bash
python3 -m venv .venv
.venv/bin/python -m pip install --upgrade pip uv
.venv/bin/uv pip install -e ".[dev]"
```

Frontend:

```bash
pnpm --dir frontend install
pnpm --dir frontend dev
```

