"""Conservative evidence-readiness evaluator. Read-only, no implicit cutover authorization."""
from collections.abc import Mapping

REQUIRED = ("inventory", "source_target_diff", "content_integrity", "acl_fidelity", "effective_access", "incremental_sync", "rollback_plan", "approval")

def evaluate(evidence):
    if not isinstance(evidence, Mapping):
        raise ValueError("Evidence must be a mapping")
    checks = {}
    for name in REQUIRED:
        entry = evidence.get(name)
        if not isinstance(entry, Mapping):
            checks[name] = "MISSING"
        elif entry.get("status") == "PASS" and isinstance(entry.get("evidence_id"), str) and entry["evidence_id"].strip():
            checks[name] = "PASS"
        elif entry.get("status") == "FAIL":
            checks[name] = "FAIL"
        else:
            checks[name] = "UNVERIFIED"
    blocked = [k for k,v in checks.items() if v != "PASS"]
    return {"decision": "REVIEW_REQUIRED" if blocked else "EVIDENCE_COMPLETE_REVIEW_REQUIRED", "cutover_authorized": False, "checks": checks, "blocked_checks": blocked, "note": "Evidence completeness is not operational approval; independent approval and runtime fencing required."}
