"""Read-only HMAC-authenticated ACL audit export, V214.8. Author: Abdelhalim Talbi.
HMAC authenticates ODMM output with an operator-managed key; it is NOT vendor attestation.
"""
import hashlib
import hmac
import json
from odmm_nas_acl_semantics_v2146 import VENDORS, compare_acl_semantics
from odmm_nas_acl_portal_v2147 import HEADERS

def canonical(value):
    return json.dumps(value,ensure_ascii=False,sort_keys=True,separators=(',',':'),allow_nan=False).encode('utf-8')

def attach_acl_signed_export(app, *, authorize, providers, hmac_key, record_export=None):
    if not callable(authorize) or type(providers) is not dict or set(providers)!=VENDORS or not all(callable(x) for x in providers.values()):
        raise ValueError('INVALID_EXPORT_DEPENDENCIES')
    if type(hmac_key) is not bytes or len(hmac_key)<32:
        raise ValueError('INVALID_AUDIT_SIGNING_KEY')
    from fastapi import Request
    from fastapi.responses import JSONResponse
    @app.get('/api/v1/operations/nas-acl-audit/export')
    def export(request:Request, source:str='', target:str='', protocol:str='NFS4'):
        try: allowed=authorize(request) is True
        except Exception: allowed=False
        if not allowed: return JSONResponse({'error':'ACCESS_DENIED'},status_code=403,headers=HEADERS)
        if (source and source not in VENDORS) or (target and target not in VENDORS) or protocol not in ('NFS4','SMB3'):
            return JSONResponse({'error':'INVALID_FILTER'},status_code=400,headers=HEADERS)
        # Snapshot each vendor once per request; a provider failure blocks every dependent pair.
        snapshots={}
        for vendor in sorted(VENDORS):
            try: snapshots[vendor]=providers[vendor](protocol)
            except Exception: snapshots[vendor]=None
        reports=[]
        for s in sorted(VENDORS):
            for t in sorted(VENDORS):
                if s==t or (source and source!=s) or (target and target!=t): continue
                row={'source':s,'target':t,'protocol':protocol,'cutover_authorized':False}
                try:
                    if s not in snapshots or t not in snapshots or snapshots[s] is None or snapshots[t] is None:
                        raise ValueError('EVIDENCE_UNAVAILABLE')
                    result=compare_acl_semantics(snapshots[s],snapshots[t])
                    if result['source_vendor']!=s or result['target_vendor']!=t: raise ValueError('VENDOR_MISMATCH')
                    row.update(status='BLOCKED',issues=result['issues'],issue_count=len(result['issues']),report_digest=result['report_digest'],blockers=result['blockers'])
                except Exception:
                    row.update(status='UNAVAILABLE',issues=[],issue_count=None,blockers=['EVIDENCE_UNAVAILABLE'])
                reports.append(row)
        payload={'schema':'odmm.nas.acl.audit.export.v2148','author':'Abdelhalim Talbi','algorithm':'HMAC-SHA256','key_id':hashlib.sha256(hmac_key).hexdigest()[:16], 'protocol':protocol,'reports':reports,'cutover_authorized':False,'vendor_attested':False}
        payload['payload_sha256']=hashlib.sha256(canonical(payload)).hexdigest()
        signature=hmac.new(hmac_key,canonical(payload),hashlib.sha256).hexdigest()
        document={**payload,'signature':signature}
        if record_export is not None:
            try: record_export(document)
            except Exception: return JSONResponse({'error':'AUDIT_PERSISTENCE_FAILED'},status_code=503,headers=HEADERS)
        return JSONResponse(document,headers={**HEADERS,'Content-Disposition':'attachment; filename="odmm-nas-acl-audit-v2148.json"'})

def verify_export(document, key):
    if type(document) is not dict or type(key) is not bytes or len(key)<32 or type(document.get('signature')) is not str: return False
    base={k:v for k,v in document.items() if k!='signature'}
    digest=base.pop('payload_sha256',None)
    if type(digest) is not str or not hmac.compare_digest(hashlib.sha256(canonical(base)).hexdigest(),digest): return False
    base['payload_sha256']=digest
    return hmac.compare_digest(hmac.new(key,canonical(base),hashlib.sha256).hexdigest(),document['signature'])
