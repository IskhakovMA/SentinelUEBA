#!/usr/bin/env bash
set -euo pipefail
python3 -m venv .venv
.venv/bin/python -m pip install --upgrade pip uv
.venv/bin/uv pip install -e ".[dev]"
pnpm --dir frontend install

