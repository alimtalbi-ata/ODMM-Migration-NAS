"""Shared, read-only dashboard for all Open Data Migration Manager editions."""
from odmm_compact_model_v2275 import filter_rows, summarize_rows

def dashboard(rows, query="", state="ALL"):
    """Return unfiltered global totals and filtered visible totals, without mutating inputs."""
    if not isinstance(rows, list) or any(not isinstance(r, dict) for r in rows):
        raise ValueError("INVALID_JOBS")
    visible = filter_rows(rows, query, state)
    return {"total": summarize_rows(rows), "visible": summarize_rows(visible), "jobs": visible,
            "read_only": True, "metrics_available": False}
