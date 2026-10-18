#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")"
python3 -m pytest -q test_odmm_payload_gate_v2285.py test_odmm_payload_gate_v2284.py test_odmm_health_v2283.py test_odmm_attention_v2281.py test_odmm_triage_v2280.py
echo "Linux Full V228.6: source qualification only; production server deployment not certified."
