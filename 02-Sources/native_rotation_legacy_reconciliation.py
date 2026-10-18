"""V194.5: fail-closed reconciliation of historical revocations with anchored HMAC chain.

Never silently imports legacy records; migration requires explicit expected heads and
an authenticated legacy gateway key. External anchor publication is caller's duty.
"""
import hashlib, hmac, json, sqlite3, time
from native_benchmark_cockpit_adapter import _canonical, _mac
from native_cockpit_audit_epochs import _connect
from native_rotation_revocation_chain import _verify, GENESIS


def _legacy(conn, gateway_key):
    if not isinstance(gateway_key, bytes) or len(gateway_key) < 32:
        raise ValueError('LEGACY_GATEWAY_KEY_INVALID')
    try:
        rows = conn.execute('SELECT request_id,payload_json,gateway_mac,recorded_ns FROM epoch_review_revocations ORDER BY request_id').fetchall()
    except sqlite3.OperationalError as exc:
        raise ValueError('LEGACY_REVOCATIONS_MISSING') from exc
    result = []
    for rid, raw, mac, timestamp in rows:
        try:
            payload = json.loads(raw)
            valid = (isinstance(payload, dict) and payload.get('request_id') == rid
                     and payload.get('decision') == 'DENY' and isinstance(timestamp, int)
                     and isinstance(mac, str) and hmac.compare_digest(mac, _mac(gateway_key, payload)))
        except (TypeError, ValueError, KeyError):
            valid = False
        if not valid:
            raise ValueError('LEGACY_REVOCATION_UNVERIFIED')
        result.append((rid, hashlib.sha256(_canonical(payload)).hexdigest()))
    return result


def reconcile_legacy_revocations(db, *, gateway_key, revocation_key, expected_head,
                                 apply=False):
    """Inspect, or explicitly import, legacy signed denials under BEGIN IMMEDIATE.

    The returned head MUST be stored in an independent trusted anchor before
    enabling a gated rotation; no external anchor is written by this function.
    """
    if type(apply) is not bool:
        raise ValueError('RECONCILIATION_MODE_INVALID')
    with _connect(db) as conn:
        conn.execute('BEGIN IMMEDIATE' if apply else 'BEGIN')
        state = _verify(conn, revocation_key)
        if not isinstance(expected_head, str) or not hmac.compare_digest(expected_head, state['head']):
            raise ValueError('REVOCATION_ANCHOR_MISMATCH')
        historical = _legacy(conn, gateway_key)
        missing = [(rid, digest) for rid, digest in historical if rid not in state['revoked']]
        if apply:
            for rid, digest in missing:
                record = {'seq': state['count']+1, 'request_id': rid,
                          'reason_sha256': digest, 'recorded_ns': time.time_ns(),
                          'previous_sha256': state['head']}
                mac = _mac(revocation_key, record)
                conn.execute('INSERT INTO epoch_revocation_chain VALUES (?,?,?,?,?,?)', (*record.values(), mac))
                state = {'count': record['seq'], 'head': hashlib.sha256(_canonical({**record,'mac_sha256':mac})).hexdigest(),
                         'revoked': state['revoked'] | {rid}}
            _verify(conn, revocation_key)
        return {'legacy_count':len(historical), 'missing_count':len(missing),
                'missing_request_ids':[rid for rid,_ in missing],
                'applied':apply, 'new_head':state['head'],
                'external_anchor_publication_required':bool(apply and missing),
                'production_qualified':False}
