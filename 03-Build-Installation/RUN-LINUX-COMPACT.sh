#!/usr/bin/env bash
# ODMM V228.25: canonical Linux Compact entry point, independent of caller CWD.
set -euo pipefail
HERE="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
ROOT="$(cd -- "$HERE/.." && pwd -P)"
SRC="$ROOT/02-Sources"
ENTRY="$SRC/odmm_linux_compact_v22811.py"
if [[ ! -f "$ENTRY" ]]; then echo 'ODMM ERROR: Linux Compact entry point missing' >&2; exit 21; fi
if ! command -v python3 >/dev/null 2>&1; then echo 'ODMM ERROR: python3 unavailable' >&2; exit 22; fi
cd -- "$SRC"
exec python3 "$ENTRY" "$@"
