#!/usr/bin/env sh
set -eu
BASE=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
cd "$BASE"
exec python3 odmm_http_runtime_qualification_v2251.py --output qualification-v2251.json
