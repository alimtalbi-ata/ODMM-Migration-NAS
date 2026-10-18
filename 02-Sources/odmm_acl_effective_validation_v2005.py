"""Read-only source/target ACL and access-evidence comparison. Author: Abdelhalim Talbi.
Evidence is supplied by an external, authenticated collector; this module NEVER executes probes.
"""
from identity_acl import ACE, IdentityMap, compare_acl
from hashlib import sha256
import json

RIGHTS = frozenset(('read','write','execute','delete','change_acl','take_ownership'))

def validate_pair(source, target, mapping, *, identity_verified=False):
    """Compare inventories keyed by safe relative path; fail closed on any missing proof.

    Each entry: aces:list[ACE], acl_complete:bool, owner:str, group:str,
    size:int, sha256:str, mode:int, mtime_ns:int, xattrs:dict,
    access:dict[(canonical_principal,right),bool|None] (attested observations).
    """
    if not isinstance(mapping, IdentityMap) or not isinstance(source,dict) or not isinstance(target,dict):
        raise ValueError('INVALID_INVENTORY_OR_MAPPING')
    paths=sorted(set(source)|set(target))
    rows=[]
    for path in paths:
        issues=[]
        if not isinstance(path,str) or not path or path.startswith('/') or any(p in ('','.', '..') for p in path.split('/')) or chr(0) in path or chr(92) in path:
            issues.append('UNSAFE_RELATIVE_PATH')
        a=source.get(path); b=target.get(path)
        if a is None: issues.append('SOURCE_ENTRY_MISSING')
        if b is None: issues.append('TARGET_ENTRY_MISSING')
        if a is not None and b is not None:
            if not isinstance(a,dict) or not isinstance(b,dict):
                issues.append('INVALID_ENTRY')
            else:
                for key in ('owner','group','size','sha256','mode','mtime_ns','xattrs'):
                    if key not in a or key not in b: issues.append('MISSING_'+key.upper())
                    elif a[key]!=b[key]: issues.append('MISMATCH_'+key.upper())
                sa=a.get('aces'); ta=b.get('aces')
                if not isinstance(sa,list) or not isinstance(ta,list) or not all(isinstance(x,ACE) for x in sa+ta):
                    issues.append('INVALID_ACL_EVIDENCE')
                else:
                    result=compare_acl(sa,ta,mapping,source_complete=a.get('acl_complete') is True,target_complete=b.get('acl_complete') is True,identity_verified=identity_verified)
                    if result['missing_mappings']: issues.append('UNMAPPED_ACL_PRINCIPAL')
                    issues.extend(result['differences'])
                    if result['status']=='BLOCKED' and not result['differences'] and not result['missing_mappings']: issues.append('ACL_BLOCKED')
                aa=a.get('access'); ba=b.get('access')
                if not isinstance(aa,dict) or not isinstance(ba,dict) or not aa:
                    issues.append('EFFECTIVE_ACCESS_EVIDENCE_MISSING')
                else:
                    if set(aa)!=set(ba): issues.append('ACCESS_TEST_COVERAGE_MISMATCH')
                    for key in set(aa)|set(ba):
                        if not isinstance(key,tuple) or len(key)!=2 or key[1] not in RIGHTS:
                            issues.append('INVALID_ACCESS_TEST_KEY'); continue
                        if type(aa.get(key)) is not bool or type(ba.get(key)) is not bool:
                            issues.append('ACCESS_TEST_NOT_ATTESTED')
                        elif aa[key]!=ba[key]: issues.append('EFFECTIVE_ACCESS_MISMATCH')
        rows.append({'path':path,'status':'BLOCKED' if issues else 'EVIDENCE_MATCHES_REQUIRES_INDEPENDENT_ATTESTATION', 'issues':sorted(set(issues))})
    if not paths: rows.append({'path':'','status':'BLOCKED','issues':['EMPTY_INVENTORY']})
    payload=json.dumps(rows,sort_keys=True,separators=(',',':')).encode()
    return {'schema':'odmm.acl.evidence.compare.v2005','author':'Abdelhalim Talbi','files':rows,
            'blocked_count':sum(x['status']=='BLOCKED' for x in rows),
            'status':'BLOCKED' if any(x['status']=='BLOCKED' for x in rows) else 'REQUIRES_INDEPENDENT_LIVE_ATTESTATION',
            'evidence_sha256':sha256(payload).hexdigest(),'cutover_authorized':False,
            'access_tests_executed':False,'writes_performed':False,'native_engine_modified':False}
