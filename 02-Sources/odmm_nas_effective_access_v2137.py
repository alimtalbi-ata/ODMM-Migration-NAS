"""Read-only effective-access comparison with injected probes; not hardware attestation.
Author: Abdelhalim Talbi.
"""
from dataclasses import dataclass
from collections.abc import Mapping
import hashlib
import json

RIGHTS = frozenset({'READ','WRITE','EXECUTE','DELETE','READ_ACL','WRITE_ACL','CHANGE_OWNER'})
VENDORS = frozenset({'netapp_ontap','pure_flashblade','dell_onefs'})

@dataclass(frozen=True)
class ProbeEvidence:
    source_digest: str
    target_digest: str
    comparison_digest: str
    discrepancies: tuple
    checked: int
    blockers: tuple
    status: str = 'BLOCKED'
    cutover_authorized: bool = False
    independently_attested: bool = False
    engine: str = 'ODMM_NATIVE'

def _text(v, code):
    if type(v) is not str or not v or len(v)>512 or any(ord(c)<32 or ord(c)==127 for c in v):
        raise ValueError(code)
    return v

def _requests(requests):
    if type(requests) not in (list,tuple) or not requests or len(requests)>10000:
        raise ValueError('INVALID_PROBE_REQUESTS')
    out=[]; seen=set()
    for r in requests:
        if not isinstance(r,Mapping) or set(r)!={'principal','path','right'}:
            raise ValueError('INVALID_PROBE_REQUEST')
        principal=_text(r['principal'],'INVALID_PRINCIPAL')
        path=_text(r['path'],'INVALID_PATH')
        if not path.startswith('/') or path.startswith('//') or any(x in ('.','..') for x in path.split('/')) or '\\' in path:
            raise ValueError('INVALID_PATH')
        right=r['right']
        if type(right) is not str or right not in RIGHTS:
            raise ValueError('INVALID_RIGHT')
        key=(principal,path,right)
        if key in seen: raise ValueError('DUPLICATE_PROBE')
        seen.add(key);out.append(key)
    return tuple(sorted(out))

def _digest(obj):
    return hashlib.sha256(json.dumps(obj,ensure_ascii=False,sort_keys=True,separators=(',',':')).encode()).hexdigest()

def compare_effective_access(*,source_vendor,target_vendor,requests,source_probe,target_probe):
    """Each injected callback receives (principal,path,right) and returns strict bool.
    Caller MUST guarantee isolated read-only probes. No actual NAS transport here.
    Any failed/unknown probe fails closed; no partial evidence returned.
    """
    if source_vendor not in VENDORS or target_vendor not in VENDORS or source_vendor==target_vendor:
        raise ValueError('UNQUALIFIED_DIRECTION')
    if not callable(source_probe) or not callable(target_probe):
        raise ValueError('INVALID_PROBE_ADAPTER')
    checks=_requests(requests)
    src=[];dst=[];diff=[]
    for principal,path,right in checks:
        try:
            a=source_probe(principal,path,right)
            b=target_probe(principal,path,right)
        except Exception as exc:
            raise ValueError('PROBE_EXECUTION_FAILED') from exc
        if type(a) is not bool or type(b) is not bool:
            raise ValueError('PROBE_RESULT_UNVERIFIED')
        src.append((principal,path,right,a));dst.append((principal,path,right,b))
        if a!=b: diff.append((principal,path,right,a,b))
    blockers=['CUTOVER_NOT_AUTHORIZED','PROBES_NOT_INDEPENDENTLY_ATTESTED','ACL_TRANSLATION_UNQUALIFIED','DISTRIBUTED_FENCING_UNVERIFIED','ROLLBACK_UNVERIFIED']
    if diff: blockers.append('EFFECTIVE_ACCESS_MISMATCH')
    return ProbeEvidence(_digest(src),_digest(dst),_digest([src,dst]),tuple(diff),len(checks),tuple(sorted(blockers)))
