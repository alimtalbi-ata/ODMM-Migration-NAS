"""Authenticated read-only JSON export of normalized NAS cross-checks.
Author: Abdelhalim Talbi. Export is advisory and always blocks cutover.
"""
from odmm_nas_consistency_v2145 import crosscheck, VENDORS

def attach_nas_consistency_export(app, *, authorize, providers):
    if not callable(authorize) or type(providers) is not dict or set(providers)!=VENDORS or not all(callable(v) for v in providers.values()):
        raise ValueError('AUTHORIZER_AND_PROVIDERS_REQUIRED')
    from fastapi import Request
    from fastapi.responses import JSONResponse
    headers={'Cache-Control':'no-store','X-Content-Type-Options':'nosniff','Content-Disposition':'attachment; filename="odmm-nas-consistency.json"'}
    @app.get('/api/v1/operations/nas-consistency/export')
    def export(request:Request):
        try: allowed=authorize(request) is True
        except Exception: allowed=False
        if not allowed: return JSONResponse({'error':'ACCESS_DENIED'},status_code=403,headers=headers)
        result=[]
        try:
            for vendor in sorted(VENDORS):
                data=providers[vendor]()
                if type(data) is not dict or set(data)!= {'namespaces','identities','accesses'}: raise ValueError('INVALID_SNAPSHOT')
                result.append(crosscheck(vendor=vendor,**data))
        except Exception:
            return JSONResponse({'error':'EVIDENCE_UNAVAILABLE','cutover_authorized':False},status_code=503,headers=headers)
        return JSONResponse({'schema':'odmm.nas.consistency.v2145','reports':result,'cutover_authorized':False,'author':'Abdelhalim Talbi'},headers=headers)
