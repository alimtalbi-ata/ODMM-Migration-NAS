"""Bounded-memory audit-chain verification; no shortcut around full integrity checking.
Author: Abdelhalim Talbi.
"""
import hashlib
import hmac
import json
from odmm_nas_acl_export_v2148 import verify_export
from odmm_nas_acl_history_v2149 import AuditHistory

class StreamingAuditHistory(AuditHistory):
    def verify_chain(self, *, batch_size=256):
        if type(batch_size) is not int or not 1 <= batch_size <= 4096:
            raise ValueError('INVALID_BATCH_SIZE')
        previous='GENESIS'
        expected_seq=1
        try:
            with self._db() as db:
                cursor=db.execute('SELECT seq,digest,previous,chain_mac,report FROM acl_audit_history ORDER BY seq')
                while True:
                    rows=cursor.fetchmany(batch_size)
                    if not rows:break
                    for seq,digest,prev,mac,raw in rows:
                        if seq != expected_seq or prev != previous:return False
                        if not hmac.compare_digest(hashlib.sha256(raw.encode()).hexdigest(),digest):return False
                        expected=hmac.new(self.key,(prev+'|'+digest).encode(),hashlib.sha256).hexdigest()
                        if not hmac.compare_digest(expected,mac):return False
                        if not verify_export(json.loads(raw),self.key):return False
                        previous=mac
                        expected_seq+=1
            return True
        except (ValueError,TypeError,KeyError,UnicodeError,json.JSONDecodeError):
            return False

def inspect_history_performance(history, *, batch_size=256):
    """Read-only metadata; full chain is checked, without materializing all rows."""
    import time
    start=time.perf_counter()
    valid=history.verify_chain(batch_size=batch_size)
    elapsed=time.perf_counter()-start
    if not valid:raise ValueError('AUDIT_INTEGRITY_FAILED')
    with history._db() as db:
        count=db.execute('SELECT COUNT(*) FROM acl_audit_history').fetchone()[0]
    return {'schema':'odmm.nas.acl.stream.v2154','records':count,
            'verification_seconds':round(elapsed,6),'batch_size':batch_size,
            'integrity_valid':True,'cutover_authorized':False,
            'qualification':'synthetic-local'}

def attach_acl_stream_status(app, *, authorize, anchored_history):
    from fastapi import Request
    from fastapi.responses import JSONResponse
    from odmm_nas_acl_portal_v2147 import HEADERS
    @app.get('/api/v1/operations/nas-acl-audit/scale/integrity')
    def status(request:Request):
        try:allowed=authorize(request) is True
        except Exception:allowed=False
        if not allowed:return JSONResponse({'error':'ACCESS_DENIED'},status_code=403,headers=HEADERS)
        try:
            if not anchored_history.verify():raise ValueError('ANCHOR_INVALID')
            result=inspect_history_performance(anchored_history.history)
            return JSONResponse(result,headers=HEADERS)
        except Exception:
            return JSONResponse({'error':'AUDIT_UNAVAILABLE','cutover_authorized':False},status_code=503,headers=HEADERS)
