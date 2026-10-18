"""Conservative NFSv4/SMB ACL semantics audit, not an authorization engine.
Author: Abdelhalim Talbi. No cutover and no vendor certification.
"""
from hashlib import sha256
import json
from collections.abc import Mapping

VENDORS=frozenset(('netapp_ontap','pure_flashblade','dell_onefs'))
RIGHTS=frozenset(('READ','WRITE','EXECUTE','DELETE','READ_ACL','WRITE_ACL','CHANGE_OWNER'))

def _digest(value):
    return sha256(json.dumps(value,sort_keys=True,separators=(',',':'),ensure_ascii=False).encode()).hexdigest()

def normalize_acl(*,vendor,protocol,share,domain,identity_map,aces,complete=False):
    if vendor not in VENDORS or protocol not in ('NFS4','SMB3') or type(complete) is not bool or not complete:
        raise ValueError('INVALID_ACL_CONTEXT')
    if any(type(s) is not str or not s.strip() or len(s)>512 for s in (share,domain)) or not share.startswith('/') or any(x in ('.','..') for x in share.split('/')):
        raise ValueError('INVALID_ACL_NAMESPACE')
    if type(identity_map) is not dict or len(identity_map)>10000 or type(aces) not in (list,tuple) or len(aces)>100000:
        raise ValueError('INVALID_ACL_DATA')
    identities={}
    for principal,canonical in identity_map.items():
        if any(type(x) is not str or not x.strip() or len(x)>512 for x in (principal,canonical)):
            raise ValueError('INVALID_IDENTITY_MAPPING')
        if canonical in identities.values():
            raise ValueError('IDENTITY_COLLISION')
        identities[principal]=canonical
    normalized=[]
    for row in aces:
        if not isinstance(row,Mapping) or set(row)!= {'ordinal','principal','effect','rights','inherited','inheritance_flags'}:
            raise ValueError('INVALID_ACE')
        if type(row['ordinal']) is not int or row['ordinal']<0 or row['principal'] not in identities or row['effect'] not in ('ALLOW','DENY') or type(row['inherited']) is not bool:
            raise ValueError('INVALID_ACE')
        rights=row['rights']; flags=row['inheritance_flags']
        if type(rights) not in (list,tuple) or not rights or any(type(r) is not str or r not in RIGHTS for r in rights) or len(set(rights))!=len(rights):
            raise ValueError('INVALID_ACE_RIGHTS')
        if type(flags) not in (list,tuple) or any(type(f) is not str or f not in ('FILE_INHERIT','DIRECTORY_INHERIT','INHERIT_ONLY','NO_PROPAGATE') for f in flags) or len(set(flags))!=len(flags):
            raise ValueError('INVALID_ACE_INHERITANCE')
        normalized.append((row['ordinal'],identities[row['principal']],row['effect'],tuple(sorted(rights)),row['inherited'],tuple(sorted(flags))))
    if len(set(r[0] for r in normalized))!=len(normalized):
        raise ValueError('DUPLICATE_ACE_ORDINAL')
    normalized.sort(key=lambda r:r[0])
    if [r[0] for r in normalized]!=list(range(len(normalized))):
        raise ValueError('NONCONTIGUOUS_ACE_ORDER')
    result={'vendor':vendor,'protocol':protocol,'share':share,'domain':domain,'aces':normalized,'identity_count':len(identities),'complete':True}
    return {**result,'digest':_digest(result),'status':'BLOCKED','cutover_authorized':False}

def compare_acl_semantics(source,target):
    if type(source) is not dict or type(target) is not dict:
        raise ValueError('INVALID_ACL_PAIR')
    for evidence in (source,target):
        if set(evidence)!= {'vendor','protocol','share','domain','aces','identity_count','complete','digest','status','cutover_authorized'}:
            raise ValueError('INVALID_ACL_EVIDENCE')
        base={k:v for k,v in evidence.items() if k not in ('digest','status','cutover_authorized')}
        if _digest(base)!=evidence['digest'] or evidence['status']!='BLOCKED' or evidence['cutover_authorized'] is not False or evidence['complete'] is not True:
            raise ValueError('TAMPERED_ACL_EVIDENCE')
    if source['vendor']==target['vendor'] or source['protocol']!=target['protocol']:
        raise ValueError('INVALID_ACL_PAIR')
    issues=[]
    for field,code in (('share','NAMESPACE_MISMATCH'),('domain','IDENTITY_DOMAIN_MISMATCH'),('aces','ACE_ORDER_OR_SEMANTICS_MISMATCH')):
        if source[field]!=target[field]: issues.append(code)
    if source['identity_count']!=target['identity_count']: issues.append('IDENTITY_COVERAGE_MISMATCH')
    report={'source_vendor':source['vendor'],'target_vendor':target['vendor'],'source_digest':source['digest'],'target_digest':target['digest'],'protocol':source['protocol'],'issues':issues,'blockers':['CUTOVER_NOT_AUTHORIZED','EFFECTIVE_ACCESS_NOT_INDEPENDENTLY_VERIFIED','VENDOR_SEMANTICS_NOT_QUALIFIED'],'status':'BLOCKED','cutover_authorized':False,'engine':'ODMM_NATIVE'}
    return {**report,'report_digest':_digest(report)}
