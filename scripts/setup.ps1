$ErrorActionPreference = "Stop"
python -m venv .venv
.\.venv\Scripts\python -m pip install --upgrade pip uv
.\.venv\Scripts\uv pip install -e ".[dev]"
pnpm --dir frontend install

