"""Read-only bounded NAS audit history overview and reproducible synthetic benchmark.
Author: Abdelhalim Talbi. No vendor performance claims.
"""
import sqlite3
import time


def audit_overview(anchored_history):
    """Fail closed: verify signed chain and external CAS anchor before metadata."""
    if not anchored_history.verify():
        raise ValueError('ANCHOR_VERIFICATION_FAILED')
    with anchored_history.history._db() as db:
        count, first, last = db.execute('SELECT COUNT(*), MIN(seq), MAX(seq) FROM acl_audit_history').fetchone()
    return {'schema':'odmm.nas.acl.scale.v2153','records':count,
            'first_sequence':first,'last_sequence':last,
            'anchor_consistent':True,'cutover_authorized':False}


def benchmark_pages(history, *, iterations=100, page_size=50):
    """Read-only benchmark; no real NAS and no implicit cutover."""
    if type(iterations) is not int or not 1 <= iterations <= 10000:
        raise ValueError('INVALID_ITERATIONS')
    if type(page_size) is not int or not 1 <= page_size <= 100:
        raise ValueError('INVALID_PAGE_SIZE')
    if not history.verify():
        raise ValueError('ANCHOR_VERIFICATION_FAILED')
    start=time.perf_counter()
    count=0
    for _ in range(iterations):
        page=history.page(cursor=0,limit=page_size)
        count+=len(page['items'])
    elapsed=time.perf_counter()-start
    return {'iterations':iterations,'page_size':page_size,'rows_read':count,
            'elapsed_seconds':round(elapsed,6),'pages_per_second':round(iterations/max(elapsed,1e-9),2),
            'environment':'synthetic-local','cutover_authorized':False}


def attach_acl_scale_status(app, *, authorize, anchored_history):
    from fastapi import Request
    from fastapi.responses import JSONResponse
    from odmm_nas_acl_portal_v2147 import HEADERS
    @app.get('/api/v1/operations/nas-acl-audit/scale/overview')
    def overview(request:Request):
        try: allowed=authorize(request) is True
        except Exception: allowed=False
        if not allowed:
            return JSONResponse({'error':'ACCESS_DENIED'},status_code=403,headers=HEADERS)
        try:
            return JSONResponse(audit_overview(anchored_history),headers=HEADERS)
        except Exception:
            return JSONResponse({'error':'AUDIT_UNAVAILABLE','cutover_authorized':False},status_code=503,headers=HEADERS)
