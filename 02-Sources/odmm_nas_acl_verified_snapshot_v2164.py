"""Fail-closed Operations integration for V216.3 snapshot, local SQLite deployment.
Author: Abdelhalim Talbi. External anchor store must be independently protected.
"""
import hmac
from fastapi import Request
from fastapi.responses import JSONResponse
from odmm_nas_acl_portal_v2147 import HEADERS
from odmm_nas_acl_snapshot_v2163 import verified_snapshot_page


def verified_anchored_snapshot(anchored_history, *, cursor=0, limit=50):
    if type(cursor) is not int or cursor < 0 or type(limit) is not int or not 1 <= limit <= 100:
        raise ValueError('INVALID_PAGE')
    history = anchored_history.history
    # BEGIN IMMEDIATE serializes SQLite writers across processes on local storage.
    # V216.3 opens its own read transaction, which is stable while this guard is held.
    with history.lock:
        with history._db() as guard:
            guard.execute('BEGIN IMMEDIATE')
            try:
                if anchored_history.inspect_recovery().get('state') != 'CONSISTENT':
                    raise RuntimeError('AUDIT_RECOVERY_REQUIRED')
                before = anchored_history._read()
                if before is None:
                    raise RuntimeError('ANCHOR_MISSING')
                result = verified_snapshot_page(history, cursor=cursor, limit=limit)
                # Exact head binding: no unanchored tail is returned as trusted.
                if (before['seq'] != result['verified_head_seq'] or
                    not hmac.compare_digest(before['chain_mac'], result['verified_head_mac'])):
                    raise RuntimeError('ANCHOR_HEAD_MISMATCH')
                after = anchored_history._read()
                if after != before or anchored_history.inspect_recovery().get('state') != 'CONSISTENT':
                    raise RuntimeError('ANCHOR_CHANGED')
                result['external_anchor_verified'] = True
                result['schema'] = 'odmm.nas.acl.verified_snapshot.v2164'
                return result
            finally:
                guard.rollback()


def attach_verified_snapshot(app, *, authorize, anchored_history):
    @app.get('/api/v1/operations/nas-acl-audit/verified-snapshot')
    def endpoint(request: Request, cursor: int = 0, limit: int = 50):
        try:
            allowed = authorize(request) is True
        except Exception:
            allowed = False
        if not allowed:
            return JSONResponse({'error':'ACCESS_DENIED'}, status_code=403, headers=HEADERS)
        try:
            result = verified_anchored_snapshot(anchored_history, cursor=cursor, limit=limit)
        except ValueError as exc:
            if str(exc) == 'INVALID_PAGE':
                return JSONResponse({'error':'INVALID_PAGE'}, status_code=400, headers=HEADERS)
            return JSONResponse({'error':'AUDIT_UNAVAILABLE','cutover_authorized':False}, status_code=503, headers=HEADERS)
        except Exception:
            return JSONResponse({'error':'AUDIT_UNAVAILABLE','cutover_authorized':False}, status_code=503, headers=HEADERS)
        return JSONResponse(result, headers=HEADERS)
