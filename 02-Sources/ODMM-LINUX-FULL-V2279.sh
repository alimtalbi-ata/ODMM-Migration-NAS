#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")"
# Full source distribution: explicit checks, no invented server entrypoint.
python3 -m pytest -q test_odmm_job_detail_v2279.py test_odmm_compact_v2275.py
echo "Open Data Migration Manager Linux Full V227.9: source/tests ready; configure and qualify deployment before production."
