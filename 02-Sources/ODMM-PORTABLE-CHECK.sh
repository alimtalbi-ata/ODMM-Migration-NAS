#!/usr/bin/env sh
set -eu
BASE=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
exec python3 "$BASE/odmm_portable_doctor_v2246.py" --root "$BASE" --output "$BASE/odmm-portable-report.json"
