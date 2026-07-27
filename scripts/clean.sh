#!/usr/bin/env bash
set -euo pipefail
if [[ -x .venv/bin/sentinelueba ]]; then
  .venv/bin/sentinelueba clean
fi
rm -rf data artifacts logs reports

