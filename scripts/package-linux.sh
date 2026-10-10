#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
.venv/bin/python -m build
printf '%s\n' 'Wheel and source distribution: dist/. Nmap and other optional engines remain external dependencies.'
