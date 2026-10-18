"""Authenticated, cross-process serialized ACL audit pages (V216.0).
Author: Abdelhalim Talbi. SQLite local lock, not a distributed filesystem lock.
"""
from fastapi import Request
from fastapi.responses import JSONResponse
from odmm_nas_acl_portal_v2147 import HEADERS


def verified_page(anchored_history, *, cursor=0, limit=50):
    if type(cursor) is not int or cursor < 0 or type(limit) is not int or not 1 <= limit <= 100:
        raise ValueError('INVALID_PAGE')
    # BEGIN IMMEDIATE prevents other SQLite writers from committing between
    # the HMAC/CAS verification and the page read, even in another process.
    # SQLite WAL readers remain permitted. Never use this on unreliable NAS locks.
    with anchored_history.history.lock:
        with anchored_history.history._db() as guard:
            guard.execute('BEGIN IMMEDIATE')
            try:
                if anchored_history.inspect_recovery().get('state') != 'CONSISTENT' or not anchored_history.verify():
                    raise RuntimeError('AUDIT_UNAVAILABLE')
                before = anchored_history._checkpoint()
                page = anchored_history.history.page(cursor=cursor, limit=limit)
                after = anchored_history._checkpoint()
                if before != after or not anchored_history.verify() or anchored_history.inspect_recovery().get('state') != 'CONSISTENT':
                    raise RuntimeError('AUDIT_CHANGED_DURING_READ')
            finally:
                guard.rollback()  # read-only guard; release reserved writer lock
    return {'schema':'odmm.nas.acl.verified_page.v2160',
            'state':'CONSISTENT','items':page['items'],
            'next_cursor':page['next_cursor'],'limit':limit,
            'verified_head_seq':before['seq'],
            'cutover_authorized':False,'vendor_attested':False}


def attach_verified_page(app, *, authorize, anchored_history):
    @app.get('/api/v1/operations/nas-acl-audit/verified-page')
    def endpoint(request:Request, cursor:int=0, limit:int=50):
        try: allowed=authorize(request) is True
        except Exception: allowed=False
        if not allowed:
            return JSONResponse({'error':'ACCESS_DENIED'},status_code=403,headers=HEADERS)
        try: result=verified_page(anchored_history,cursor=cursor,limit=limit)
        except ValueError:
            return JSONResponse({'error':'INVALID_PAGE'},status_code=400,headers=HEADERS)
        except Exception:
            return JSONResponse({'error':'AUDIT_UNAVAILABLE','cutover_authorized':False},status_code=503,headers=HEADERS)
        return JSONResponse(result,headers=HEADERS)
