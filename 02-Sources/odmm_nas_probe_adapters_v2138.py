"""Vendor-scoped, non-destructive access evidence adapters (no hardware claims).
Author: Abdelhalim Talbi.

Injected collector must be independently implemented and qualified by the deployer.
This module never executes access-changing operations or authenticates a vendor API.
"""
from collections.abc import Mapping
from dataclasses import dataclass
from hashlib import sha256
import json
from odmm_nas_effective_access_v2137 import RIGHTS, VENDORS, compare_effective_access

@dataclass(frozen=True)
class ReadOnlyEvidence:
    vendor: str
    firmware: str
    collection_id: str
    observations: tuple
    digest: str
    blockers: tuple = ('VENDOR_COLLECTOR_NOT_INDEPENDENTLY_QUALIFIED', 'NONDESTRUCTIVE_ACCESS_NOT_ATTESTED')
    cutover_authorized: bool = False
    independently_attested: bool = False
    engine: str = 'ODMM_NATIVE'

def _string(value, code, limit=256):
    if type(value) is not str or not value.strip() or len(value)>limit or any(ord(c)<32 or ord(c)==127 for c in value):
        raise ValueError(code)
    return value

def collect_readonly_evidence(*, vendor, firmware, collection_id, requests, collector):
    """Collector(principal,path,right) returns a Mapping with decision and metadata.
    The caller must ensure collector uses read-only vendor operations and trusted TLS.
    WRITE/DELETE/CHANGE_OWNER decisions are only *reported*, never exercised.
    """
    if vendor not in VENDORS: raise ValueError('UNSUPPORTED_VENDOR')
    firmware=_string(firmware,'INVALID_FIRMWARE')
    collection_id=_string(collection_id,'INVALID_COLLECTION_ID')
    if not callable(collector): raise ValueError('INVALID_COLLECTOR')
    from odmm_nas_effective_access_v2137 import _requests
    normalized=_requests(requests)
    rows=[]
    for principal,path,right in normalized:
        try: response=collector(principal,path,right)
        except Exception as exc: raise ValueError('COLLECTOR_FAILED') from exc
        if not isinstance(response,Mapping) or set(response)!={'allowed','method','identity_resolved'}:
            raise ValueError('INVALID_COLLECTOR_RESPONSE')
        if type(response['allowed']) is not bool or response['identity_resolved'] is not True:
            raise ValueError('UNVERIFIED_COLLECTOR_RESPONSE')
        method=response['method']
        if method not in ('ACL_READONLY','VENDOR_PERMISSION_QUERY') or type(method) is not str:
            raise ValueError('UNSAFE_PROBE_METHOD')
        rows.append((principal,path,right,response['allowed'],method))
    payload={'schema':'odmm.nas.readonly.v2138','vendor':vendor,'firmware':firmware,'collection_id':collection_id,'rows':rows}
    digest=sha256(json.dumps(payload,ensure_ascii=False,sort_keys=True,separators=(',',':')).encode()).hexdigest()
    return ReadOnlyEvidence(vendor,firmware,collection_id,tuple(rows),digest)

def compare_collected_evidence(source, target):
    if type(source) is not ReadOnlyEvidence or type(target) is not ReadOnlyEvidence or source.vendor==target.vendor:
        raise ValueError('INVALID_EVIDENCE_PAIR')
    if source.vendor not in VENDORS or target.vendor not in VENDORS or source.cutover_authorized or target.cutover_authorized or source.independently_attested or target.independently_attested:
        raise ValueError('UNTRUSTED_EVIDENCE')
    for evidence in (source,target):
        if type(evidence.observations) is not tuple or not evidence.observations or not all(type(row) is tuple and len(row)==5 for row in evidence.observations):
            raise ValueError('INVALID_EVIDENCE_ROWS')
        payload={'schema':'odmm.nas.readonly.v2138','vendor':evidence.vendor,'firmware':evidence.firmware,'collection_id':evidence.collection_id,'rows':evidence.observations}
        expected=sha256(json.dumps(payload,ensure_ascii=False,sort_keys=True,separators=(',',':')).encode()).hexdigest()
        if expected!=evidence.digest: raise ValueError('EVIDENCE_DIGEST_MISMATCH')
    src={(p,path,right):allowed for p,path,right,allowed,method in source.observations}
    dst={(p,path,right):allowed for p,path,right,allowed,method in target.observations}
    if len(src)!=len(source.observations) or len(dst)!=len(target.observations) or set(src)!=set(dst):
        raise ValueError('INCOMPLETE_PROBE_COVERAGE')
    requests=[dict(principal=p,path=path,right=right) for p,path,right in sorted(src)]
    result=compare_effective_access(source_vendor=source.vendor,target_vendor=target.vendor,requests=requests,
        source_probe=lambda p,path,right:src[(p,path,right)],target_probe=lambda p,path,right:dst[(p,path,right)])
    return {'source_vendor':source.vendor,'target_vendor':target.vendor,'source_digest':source.digest,
        'target_digest':target.digest,'comparison_digest':result.comparison_digest,'checked':result.checked,
        'discrepancies':[list(d) for d in result.discrepancies],
        'blockers':sorted(set(result.blockers)|set(source.blockers)|set(target.blockers)),
        'status':'BLOCKED','cutover_authorized':False,'independently_attested':False,'engine':'ODMM_NATIVE'}

def attach_nas_access_audit(app, *, authorize, providers):
    """Attach authenticated read-only JSON route to existing ODMM Operations app."""
    if not callable(authorize) or type(providers) is not dict or set(providers)!=VENDORS or not all(callable(x) for x in providers.values()):
        raise ValueError('AUTHORIZER_AND_PROVIDERS_REQUIRED')
    from fastapi import Request
    from fastapi.responses import JSONResponse
    @app.get('/api/v1/operations/nas-access/{source}/{target}')
    def access_audit(request:Request,source:str,target:str):
        headers={'Cache-Control':'no-store','X-Content-Type-Options':'nosniff'}
        try: allowed=authorize(request) is True
        except Exception: allowed=False
        if not allowed: return JSONResponse({'error':'ACCESS_DENIED'},status_code=403,headers=headers)
        if source not in VENDORS or target not in VENDORS or source==target:
            return JSONResponse({'error':'UNSUPPORTED_DIRECTION'},status_code=400,headers=headers)
        try: result=compare_collected_evidence(providers[source](),providers[target]())
        except Exception: return JSONResponse({'error':'EVIDENCE_UNAVAILABLE','cutover_authorized':False},status_code=503,headers=headers)
        return JSONResponse(result,headers=headers)
