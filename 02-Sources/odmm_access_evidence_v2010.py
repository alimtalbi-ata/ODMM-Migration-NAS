"""ODMM V201.0: read-only access observations and fail-closed evidence matrix.
Author: Abdelhalim Talbi. No impersonation, write probes or cutover approval.
"""
import hashlib, json, os
from readonly_access_probe import probe_readonly, AccessProbeError

RIGHTS = frozenset(("read", "write", "execute", "delete", "change_acl", "take_ownership"))

def collect_read_observation(root, relative_path, *, expected_euid, expected_egid=None):
    """Observe only read-open under the existing OS identity, without reading contents."""
    result = probe_readonly(root, relative_path, expected_euid=expected_euid, expected_egid=expected_egid)
    report = result["report"]
    return {"right":"read", "outcome":report["outcome"], "euid":report["execution_euid"],
            "egid":report["execution_egid"], "sha256":result["sha256"],
            "identity_attested":False, "server_attested":False, "writes_performed":False}

def compare_access_evidence(source, target, *, required_rights=("read", "write", "execute")):
    """Compare provided observations by (path, identity, right).

    Observations must be dicts keyed by (relative_path, canonical_identity, right),
    with values {'outcome': 'ALLOW'|'DENY', 'server_attested': bool,
    'identity_attested': bool}. Missing evidence is never treated as DENY.
    This report NEVER grants cutover, even if every observation is attested.
    """
    if not isinstance(source,dict) or not isinstance(target,dict):
        raise ValueError("INVALID_EVIDENCE")
    if not required_rights or any(r not in RIGHTS for r in required_rights):
        raise ValueError("INVALID_REQUIRED_RIGHTS")
    rows=[]
    for key in sorted(set(source)|set(target),key=repr):
        issues=[]
        if not isinstance(key,tuple) or len(key)!=3 or not all(isinstance(v,str) for v in key):
            issues.append("INVALID_EVIDENCE_KEY")
        else:
            path,identity,right=key
            if not path or path.startswith('/') or '\\' in path or any(p in ('','.','..') for p in path.split('/')) or not identity or right not in RIGHTS:
                issues.append("INVALID_EVIDENCE_KEY")
        a=source.get(key); b=target.get(key)
        if a is None or b is None: issues.append("MISSING_SOURCE_OR_TARGET_OBSERVATION")
        if a is not None and b is not None:
            if not isinstance(a,dict) or not isinstance(b,dict):issues.append("INVALID_OBSERVATION")
            else:
                for v in (a,b):
                    if v.get('outcome') not in ('ALLOW','DENY'):issues.append("INVALID_OUTCOME")
                    if v.get('server_attested') is not True or v.get('identity_attested') is not True:
                        issues.append("REMOTE_IDENTITY_OR_SERVER_NOT_ATTESTED")
                if a.get('outcome')!=b.get('outcome'):issues.append("EFFECTIVE_ACCESS_MISMATCH")
        rows.append({'key':list(key) if isinstance(key,tuple) else repr(key),'issues':sorted(set(issues)),
                     'status':'BLOCKED' if issues else 'MATCHED_EVIDENCE_NOT_CUTOVER_AUTHORIZATION'})
    if not rows: rows.append({'key':[],'issues':['EMPTY_EVIDENCE'],'status':'BLOCKED'})
    covered={key[2] for key in set(source)&set(target) if isinstance(key,tuple) and len(key)==3}
    missing=sorted(set(required_rights)-covered)
    if missing: rows.append({'key':[],'issues':['REQUIRED_RIGHTS_NOT_COVERED:'+','.join(missing)],'status':'BLOCKED'})
    payload={'schema':'odmm.access.evidence.v2010','author':'Abdelhalim Talbi','rows':rows,
             'status':'BLOCKED' if any(x['status']=='BLOCKED' for x in rows) else 'EVIDENCE_MATCH_REQUIRES_INDEPENDENT_QUALIFICATION',
             'cutover_authorized':False,'writes_performed':False,'native_engine_modified':False}
    payload['evidence_sha256']=hashlib.sha256(json.dumps(payload,sort_keys=True,separators=(',',':')).encode()).hexdigest()
    return payload
