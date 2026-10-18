"""Conservative ACL/identity snapshot comparison; no effective-access claims.
Author: Abdelhalim Talbi.
"""
from collections.abc import Mapping
from dataclasses import dataclass
import hashlib
import json

@dataclass(frozen=True)
class AccessSnapshot:
    vendor: str
    endpoint_id: str
    acl_model: str
    identity_domain: str
    entries: tuple
    digest: str
    blockers: tuple = ('EFFECTIVE_ACCESS_NOT_PROBED','ACL_FIDELITY_NOT_INDEPENDENTLY_VERIFIED')
    cutover_authorized: bool = False


def normalize_access(*, vendor, endpoint_id, acl_model, identity_domain, entries, complete=False):
    from odmm_nas_share_inventory_v2133 import VENDORS
    if vendor not in VENDORS or not all(isinstance(x,str) and x.strip() and len(x)<256 for x in (endpoint_id,acl_model,identity_domain)):
        raise ValueError('INVALID_ACCESS_IDENTITY')
    if complete is not True or type(entries) not in (list,tuple) or len(entries)>100000:
        raise ValueError('INCOMPLETE_ACCESS_SNAPSHOT')
    normalized=[]
    for e in entries:
        if not isinstance(e,Mapping) or set(e)!={'path','principal','effect','rights','inherited','ordinal'}:
            raise ValueError('INVALID_ACE')
        if not all(isinstance(e[k],str) and e[k].strip() and len(e[k])<2048 for k in ('path','principal')) or not e['path'].startswith('/') or any(p in ('.','..') for p in e['path'].split('/')):
            raise ValueError('INVALID_ACE_PATH')
        if e['effect'] not in ('ALLOW','DENY') or type(e['inherited']) is not bool or type(e['ordinal']) is not int or e['ordinal']<0:
            raise ValueError('INVALID_ACE_FLAGS')
        if type(e['rights']) not in (list,tuple) or not e['rights'] or any(not isinstance(r,str) or not r or len(r)>64 for r in e['rights']) or len(set(e['rights']))!=len(e['rights']):
            raise ValueError('INVALID_ACE_RIGHTS')
        normalized.append((e['path'],e['ordinal'],e['principal'],e['effect'],tuple(sorted(e['rights'])),e['inherited']))
    if len(set((e[0],e[1]) for e in normalized))!=len(normalized):
        raise ValueError('DUPLICATE_ACE_ORDINAL')
    normalized=tuple(sorted(normalized))
    digest=hashlib.sha256(json.dumps([vendor,endpoint_id,acl_model,identity_domain,normalized],ensure_ascii=False,separators=(',',':')).encode()).hexdigest()
    return AccessSnapshot(vendor,endpoint_id,acl_model,identity_domain,normalized,digest)


def compare_access(source,target):
    if type(source) is not AccessSnapshot or type(target) is not AccessSnapshot or source.vendor==target.vendor:
        raise ValueError('INVALID_ACCESS_PAIR')
    blockers=set(source.blockers+target.blockers+('CUTOVER_NOT_AUTHORIZED','IDENTITY_MAPPING_UNVERIFIED'))
    if source.acl_model!=target.acl_model: blockers.add('ACL_MODEL_MISMATCH')
    if source.identity_domain!=target.identity_domain: blockers.add('IDENTITY_DOMAIN_MISMATCH')
    if source.entries!=target.entries: blockers.add('ACE_ORDER_OR_CONTENT_MISMATCH')
    return {'status':'BLOCKED','source_digest':source.digest,'target_digest':target.digest,'blockers':sorted(blockers),'cutover_authorized':False,'engine':'ODMM_NATIVE'}
