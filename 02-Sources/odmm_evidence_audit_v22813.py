"""Offline cross-check of evidence provenance. No cutover authority."""
from collections.abc import Mapping
from odmm_market_readiness_v22812 import REQUIRED, evaluate

def audit(evidence, expected_job_id=None):
    base = evaluate(evidence)
    anomalies = []
    seen = set()
    for key in REQUIRED:
        entry = evidence.get(key)
        if not isinstance(entry, Mapping) or base["checks"][key] != "PASS":
            continue
        eid = entry["evidence_id"].strip()
        if eid in seen:
            anomalies.append({"check": key, "reason": "DUPLICATE_EVIDENCE_ID"})
        seen.add(eid)
        if expected_job_id is not None and entry.get("job_id") != expected_job_id:
            anomalies.append({"check": key, "reason": "JOB_BINDING_MISMATCH"})
    return {**base, "decision": "REVIEW_REQUIRED" if anomalies or base["blocked_checks"] else "EVIDENCE_COMPLETE_REVIEW_REQUIRED", "anomalies": anomalies, "cutover_authorized": False}
