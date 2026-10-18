"""Shared read-only operational summary. No completion implies ACL or cutover approval."""
from collections import Counter
STATES = ("RUNNING", "FAILED", "PENDING", "COMPLETED", "UNKNOWN")

def supervision(rows):
    if not isinstance(rows, list):
        raise ValueError("registry must be a list")
    counts = Counter()
    for row in rows:
        if not isinstance(row, dict):
            raise ValueError("job must be an object")
        status = str(row.get("status", "UNKNOWN")).upper()
        if status not in STATES:
            raise ValueError("unknown job status")
        counts[status] += 1
    return {"total": len(rows), "running": counts["RUNNING"], "failed": counts["FAILED"], "pending": counts["PENDING"], "completed_unverified": counts["COMPLETED"], "unknown": counts["UNKNOWN"], "needs_review": counts["FAILED"] + counts["UNKNOWN"], "cutover_approved": False, "read_only": True}

def overview_lines(summary):
    return ["Jobs %s | Actifs %s | En attente %s | Échecs %s | Inconnus %s | Terminés (non certifiés) %s" % (summary["total"], summary["running"], summary["pending"], summary["failed"], summary["unknown"], summary["completed_unverified"]), "À examiner : %s | Bascule autorisée : NON (preuves requises)" % summary["needs_review"]]
