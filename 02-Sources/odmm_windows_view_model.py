"""Pure presentation model for Windows Compact registry table.

No Tk imports, no IO and no mutation of incoming jobs. This module only
prepares existing dashboard, sort and pagination results for rendering.
"""
from odmm_compact_dashboard_v2280 import dashboard
from odmm_attention_v2281 import attention_summary
from odmm_health_v2283 import assess
from odmm_pagination_v22859 import paginate, sort_jobs
from odmm_ui_state_v22811 import selection_after_filter

KNOWN_STATES = frozenset({"FAILED", "RUNNING", "COMPLETED", "PENDING"})


def build_jobs_view(rows, query, state, column, reverse, page, size, selected_ids=()):
    view = dashboard(rows, query, state)
    visible = sort_jobs(view["jobs"], column, reverse)
    page_rows, page_number, page_count = paginate(visible, page, size)
    selected = selection_after_filter(selected_ids, visible)
    rendered = []
    for job in page_rows:
        normalized = str(job.get("status", "UNKNOWN")).strip().upper()
        rendered.append({
            "id": job.get("id", ""),
            "status": job.get("status", ""),
            "tag": normalized if normalized in KNOWN_STATES else "UNKNOWN",
            "selected": str(job.get("id", "")) in selected,
        })
    counts = view["visible"]
    overall = view["total"]
    attention = attention_summary(rows)
    health = assess(rows)
    return {
        "rows": rendered,
        "page": page_number,
        "pages": page_count,
        "visible_count": len(visible),
        "page_label": f"Page {page_number + 1} / {page_count} · {len(visible)} résultats filtrés",
        "summary": (
            f"Total : {overall['total']}  |  En cours : {overall['running']}"
            f"  |  Échecs : {attention['failed']}  |  À examiner : {attention['needs_attention']}"
            f"  |  Affichés : {counts['total']}  |  Diagnostic : {health['level']}"
        ),
    }
