#!/usr/bin/env bash
# ODMM V228.26 — qualification Linux Full non destructive
set -euo pipefail
HERE="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
ROOT="$(cd -- "$HERE/.." && pwd -P)"
SRC="$ROOT/02-Sources"
TEST="test_odmm_market_readiness_v22812"
if [[ ! -f "$SRC/$TEST.py" ]]; then echo "FAIL|missing-full-qualification-test" >&2; exit 31; fi
if ! command -v python3 >/dev/null 2>&1; then echo "FAIL|python3-unavailable" >&2; exit 32; fi
case "${1:---help}" in
  --help|-h) printf '%s\n' 'ODMM Linux Full qualification (read-only)' 'Usage: RUN-LINUX-FULL.sh --check | --help' 'Does not start a NAS migration.';;
  --check) (cd -- "$SRC" && python3 -m unittest -q "$TEST") && echo 'PASS|linux-full-evidence-tests;nas-live=NOT_QUALIFIED';;
  *) echo 'FAIL|unsupported-command' >&2; exit 33;;
esac
