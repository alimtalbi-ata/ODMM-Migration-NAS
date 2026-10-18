"""Read-only, privacy-minimized operational export. Never includes credentials or job payloads."""
import json
from pathlib import Path
from odmm_supervision_v2287 import supervision

def summary_document(rows):
    stats = supervision(rows)
    return {"schema": "odmm.supervision.summary.v1", "edition": "Open Data Migration Manager", "read_only": True, "contains_job_details": False, "cutover_approved": False, "summary": stats, "warning": "COMPLETED does not certify ACL, checksum or cutover."}

def write_summary(rows, destination):
    """Create new export exclusively; never overwrite an existing file."""
    target = Path(destination)
    content = json.dumps(summary_document(rows), indent=2, ensure_ascii=False) + "\n"
    with target.open("x", encoding="utf-8") as output:
        output.write(content)
    return target
