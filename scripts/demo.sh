#!/usr/bin/env bash
set -euo pipefail
.venv/bin/sentinelueba init
.venv/bin/sentinelueba generate-demo --seed 42
.venv/bin/sentinelueba train --seed 42
.venv/bin/sentinelueba detect
.venv/bin/sentinelueba status

