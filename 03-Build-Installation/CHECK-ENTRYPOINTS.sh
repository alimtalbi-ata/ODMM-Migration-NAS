#!/usr/bin/env bash
set -euo pipefail
HERE="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
ROOT="$(cd -- "$HERE/.." && pwd -P)"
for file in "02-Sources/odmm_linux_compact_v22811.py" "02-Sources/odmm_windows_compact_v22811.py" "02-Sources/BUILD-WINDOWS-COMPACT-V22811.cmd" "02-Sources/ODMM-COMPACT-WINDOWS-V22811.iss" "03-Build-Installation/BUILD-WINDOWS-COMPACT.cmd" "03-Build-Installation/RUN-LINUX-COMPACT.sh" "03-Build-Installation/RUN-LINUX-FULL.sh" "02-Sources/test_odmm_market_readiness_v22812.py"; do
  if [[ ! -f "$ROOT/$file" ]]; then printf 'FAIL missing %s\n' "$file" >&2; exit 20; fi
  printf 'PASS %s\n' "$file"
done
