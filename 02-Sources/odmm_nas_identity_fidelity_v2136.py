"""Fail-closed identity and ordered ACL mapping preflight, not a live access probe.
Author: Abdelhalim Talbi.
"""
from dataclasses import dataclass
from collections.abc import Mapping
import re, hashlib, json
from odmm_nas_acl_identity_v2135 import AccessSnapshot

SID = re.compile(r"S-1-[0-9]+(?:-[0-9]+){1,14}\Z")
@dataclass(frozen=True)
class IdentityMap:
    entries: tuple
    digest: str
    complete: bool
    cutover_authorized: bool = False


def _identity(value):
    if not isinstance(value, Mapping) or set(value) != {'domain','name','sid','uid','gid'}:
        raise ValueError('INVALID_IDENTITY')
    domain, name, sid, uid, gid = (value[k] for k in ('domain','name','sid','uid','gid'))
    if not all(type(x) is str and x.strip() and len(x)<=256 and not any(ord(c)<32 for c in x) for x in (domain,name)):
        raise ValueError('INVALID_IDENTITY_NAME')
    if sid is not None and (type(sid) is not str or not SID.fullmatch(sid)):
        raise ValueError('INVALID_SID')
    if any(v is not None and (type(v) is not int or v<0 or v>4294967295) for v in (uid,gid)):
        raise ValueError('INVALID_UNIX_ID')
    if sid is None and uid is None and gid is None:
        raise ValueError('IDENTITY_UNRESOLVED')
    return (domain,name,sid,uid,gid)


def build_mapping(pairs, *, complete=False):
    if complete is not True or type(pairs) not in (list,tuple) or not pairs or len(pairs)>100000:
        raise ValueError('INCOMPLETE_IDENTITY_MAPPING')
    result=[]; sources=set(); targets=set()
    for pair in pairs:
        if not isinstance(pair,Mapping) or set(pair)!={'source','target'}:
            raise ValueError('INVALID_MAPPING_PAIR')
        source=_identity(pair['source']); target=_identity(pair['target'])
        if source in sources or target in targets:
            raise ValueError('IDENTITY_MAPPING_COLLISION')
        sources.add(source); targets.add(target); result.append((source,target))
    result=tuple(sorted(result,key=lambda p:json.dumps(p,ensure_ascii=False)))
    digest=hashlib.sha256(json.dumps(result,ensure_ascii=False,separators=(',',':')).encode()).hexdigest()
    return IdentityMap(result,digest,True)


def assess_fidelity(source, target, identity_map, *, access_probes=None):
    if type(source) is not AccessSnapshot or type(target) is not AccessSnapshot or type(identity_map) is not IdentityMap:
        raise ValueError('INVALID_ASSESSMENT')
    if source.vendor==target.vendor:
        raise ValueError('SAME_VENDOR_UNQUALIFIED')
    blockers={'CUTOVER_NOT_AUTHORIZED','NO_INDEPENDENT_EFFECTIVE_ACCESS_PROOF','DISTRIBUTED_FENCING_UNVERIFIED','ROLLBACK_UNVERIFIED','ACL_TRANSLATION_UNQUALIFIED'}
    if source.acl_model != target.acl_model: blockers.add('ACL_MODEL_TRANSLATION_REQUIRED')
    if source.identity_domain != target.identity_domain: blockers.add('CROSS_DOMAIN_MAPPING_REQUIRES_VERIFICATION')
    if source.entries != target.entries: blockers.add('ACE_ORDER_OR_CONTENT_MISMATCH')
    mapped={p[0][1] for p in identity_map.entries}
    used={e[2] for e in source.entries}
    if not used.issubset(mapped): blockers.add('UNMAPPED_ACL_PRINCIPALS')
    # Caller-provided probes are not independent evidence. Never treat them as proof.
    if access_probes is not None: blockers.add('SUPPLIED_ACCESS_PROBES_UNATTESTED')
    return {'status':'BLOCKED','engine':'ODMM_NATIVE','blockers':sorted(blockers),'identity_mapping_digest':identity_map.digest,'source_acl_digest':source.digest,'target_acl_digest':target.digest,'cutover_authorized':False,'effective_access_verified':False,'acl_fidelity_verified':False}
