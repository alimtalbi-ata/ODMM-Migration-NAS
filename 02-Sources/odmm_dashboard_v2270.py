"""Pure read-only dashboard filters; no state transitions or writes."""
from datetime import datetime, timezone


def filter_jobs(rows, query='', status='Tous'):
    needle = query.strip().casefold()
    return [r for r in rows if (status == 'Tous' or r['status'] == status) and
            (not needle or needle in r['id'].casefold() or needle in r['status'].casefold())]


def lease_indicator(op, now=None):
    """Only timezone-aware ISO timestamps can establish expiration."""
    if op['state'] != 'RUNNING' or op.get('lease_until') is None:
        return '—'
    raw = op['lease_until']
    if not isinstance(raw, str):
        return 'Inconnu'
    try:
        dt = datetime.fromisoformat(raw.replace('Z', '+00:00'))
    except ValueError:
        return 'Inconnu'
    if dt.tzinfo is None:
        return 'Inconnu'
    current = now or datetime.now(timezone.utc)
    return 'Expiré (horloge locale)' if dt < current else 'Actif (horloge locale)'


def filter_operations(rows, query='', state='Tous', expired_only=False, now=None):
    needle = query.strip().casefold()
    return [r for r in rows if (state == 'Tous' or r['state'] == state) and
            (not needle or needle in (r['id'] + ' ' + (r.get('owner') or '')).casefold()) and
            (not expired_only or lease_indicator(r, now).startswith('Expiré'))]
