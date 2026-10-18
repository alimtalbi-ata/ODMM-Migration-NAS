"""Read-only supervisory health assessment; never authorizes migration or cutover."""
from collections import Counter

KNOWN = frozenset(("PENDING", "RUNNING", "FAILED", "COMPLETED", "UNKNOWN"))
def assess(rows):
    if not isinstance(rows, list) or any(not isinstance(r, dict) for r in rows):
        raise ValueError("INVALID_JOBS")
    ids = [str(r.get("id", "")).strip() for r in rows]
    statuses = [r.get("status") for r in rows]
    duplicates = sorted(k for k,v in Counter(i for i in ids if i).items() if v > 1)
    missing_ids = sum(not i for i in ids)
    invalid_states = sum(not isinstance(v,str) or v not in KNOWN for v in statuses)
    failed = sum(v == "FAILED" for v in statuses)
    unknown = sum(v == "UNKNOWN" for v in statuses)
    if duplicates or missing_ids or invalid_states:
        level = "DATA_QUALITY"
    elif failed or unknown:
        level = "ATTENTION"
    elif not rows:
        level = "NO_DATA"
    else:
        level = "NO_ALERT_DETECTED"
    return {"level":level,"total":len(rows),"failed":failed,"unknown":unknown,
            "missing_ids":missing_ids,"duplicate_ids":duplicates,"invalid_states":invalid_states,
            "read_only":True,"cutover_authorized":False,
            "note":"Supervision only: no ACL, checksum, migration success or cutover certification"}
