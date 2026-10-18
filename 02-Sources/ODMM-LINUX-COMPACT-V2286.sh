#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")"
exec python3 odmm_linux_compact_v2286.py "$@"
