"""Read-only Operations audit diagnostics with verified external anchor.
Author: Abdelhalim Talbi. Local evidence only, no vendor qualification.
"""
import time
from fastapi import Request
from fastapi.responses import JSONResponse
from odmm_nas_acl_portal_v2147 import HEADERS

def inspect_operations(anchored_history):
    started=time.perf_counter()
    state=anchored_history.inspect_recovery()
    status=state.get('state','VERIFICATION_ERROR')
    if status!='CONSISTENT' or not anchored_history.verify():
        raise ValueError('AUDIT_NOT_CONSISTENT')
    with anchored_history.history._db() as db:
        count=db.execute('SELECT COUNT(*) FROM acl_audit_history').fetchone()[0]
        head=db.execute('SELECT COALESCE(MAX(seq),0) FROM acl_audit_history').fetchone()[0]
    if count!=head:raise ValueError('AUDIT_SEQUENCE_GAP')
    return {'schema':'odmm.nas.acl.operations.v2157','state':'CONSISTENT',
            'records':count,'head_seq':head,
            'verification_seconds':round(time.perf_counter()-started,6),
            'cutover_authorized':False,'vendor_attested':False}

def attach_operations_diagnostics(app, *, authorize, anchored_history):
    @app.get('/api/v1/operations/nas-acl-audit/diagnostics')
    def diagnostics(request:Request):
        try: allowed=authorize(request) is True
        except Exception: allowed=False
        if not allowed:return JSONResponse({'error':'ACCESS_DENIED'},status_code=403,headers=HEADERS)
        try:return JSONResponse(inspect_operations(anchored_history),headers=HEADERS)
        except Exception:return JSONResponse({'error':'AUDIT_UNAVAILABLE','cutover_authorized':False},status_code=503,headers=HEADERS)
