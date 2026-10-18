"""Pure presentation helpers for the Windows Compact read-only client."""
ALLOWED = {"ALL", "PENDING", "RUNNING", "FAILED", "COMPLETED", "UNKNOWN"}

def filter_rows(rows, query="", state="ALL"):
    if state not in ALLOWED:
        raise ValueError("INVALID_FILTER")
    needle = query.strip().casefold()
    return [dict(row) for row in rows if (state == "ALL" or row.get("status") == state)
            and (not needle or needle in str(row.get("id", "")).casefold())]

def summarize_rows(rows):
    counts = {"total": len(rows), "running": 0, "failed": 0, "completed": 0, "pending": 0}
    for row in rows:
        state = row.get("status")
        if state == "RUNNING": counts["running"] += 1
        elif state == "FAILED": counts["failed"] += 1
        elif state == "COMPLETED": counts["completed"] += 1
        elif state == "PENDING": counts["pending"] += 1
    return counts
