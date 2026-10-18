"""Read-only operational summaries. Indicators are observations, not server decisions."""
from odmm_dashboard_v2270 import lease_indicator

def summarize(jobs, operations, now=None):
    """Counts independent statuses; unknown leases are never called expired."""
    jobs=list(jobs); operations=list(operations)
    return {
        'jobs_total': len(jobs),
        'jobs_blocked': sum(j.get('status') == 'BLOCKED' for j in jobs),
        'jobs_failed': sum(j.get('status') == 'FAILED' for j in jobs),
        'operations_total': len(operations),
        'operations_failed': sum(o.get('state') == 'FAILED' for o in operations),
        'leases_expired_local': sum(lease_indicator(o, now).startswith('Expiré') for o in operations),
        'leases_unknown': sum(lease_indicator(o, now) == 'Inconnu' for o in operations),
    }

def format_summary(s):
    return (f"Jobs : {s['jobs_total']} · bloqués : {s['jobs_blocked']} · échecs : {s['jobs_failed']}  |  "
            f"Opérations : {s['operations_total']} · échecs : {s['operations_failed']} · "
            f"leases expirés (horloge locale) : {s['leases_expired_local']} · inconnus : {s['leases_unknown']}")
