#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")"
python3 -m pytest -q test_odmm_release_v2284.py test_odmm_health_v2284.py test_odmm_attention_v2281.py test_odmm_triage_v2280.py
echo "Linux Full V228.4: source qualification only; production server deployment not certified."
