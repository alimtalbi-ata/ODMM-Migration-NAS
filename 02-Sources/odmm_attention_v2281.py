"""Safe read-only actionable summary for all ODMM editions."""
from odmm_compact_dashboard_v2280 import dashboard

def attention_summary(rows):
    view = dashboard(rows)
    failed = []
    unknown = []
    running = []
    for row in view["jobs"]:
        state = str(row.get("status", "UNKNOWN")).strip().upper()
        if state == "FAILED": failed.append(dict(row))
        elif state not in {"RUNNING", "PENDING", "COMPLETED"}: unknown.append(dict(row))
        elif state == "RUNNING": running.append(dict(row))
    return {"total": len(rows), "failed": len(failed), "unknown": len(unknown),
            "running": len(running), "needs_attention": len(failed) + len(unknown),
            "jobs": failed + unknown, "read_only": True,
            "note": "Statuts déclarés, non une validation des données ou des ACL."}
