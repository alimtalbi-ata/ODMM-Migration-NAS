"""Read-only payload quality gate. Rejects malformed or ambiguous job identity."""
from odmm_health_v2283 import assess

def validate_jobs(rows):
    health = assess(rows)
    if health["missing_ids"] or health["duplicate_ids"] or health["invalid_states"]:
        raise ValueError("INVALID_REGISTRY_QUALITY")
    return rows
