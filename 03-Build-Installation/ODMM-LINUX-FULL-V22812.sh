#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")"
python3 -m unittest -q test_odmm_market_readiness_v22812
echo "ODMM V228.12: targeted evidence checks PASS; NAS migration not qualified"
