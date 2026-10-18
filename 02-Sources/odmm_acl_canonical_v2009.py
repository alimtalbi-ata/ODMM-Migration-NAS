"""Conservative NFSv4/SMB ACL normalization and identity mapping. Author: Abdelhalim Talbi.
Read-only; unknown flags, rights or principals remain BLOCKED. No effective-access claims.
"""
import hashlib
import json
import re
from identity_acl import ACE, Principal, IdentityMap, compare_acl

NFS_RIGHTS={"r":"read","w":"write","x":"execute","d":"delete","C":"change_acl","o":"take_ownership"}
SMB_RIGHTS={"READ":"read","WRITE":"write","EXECUTE":"execute","DELETE":"delete","WRITE_DAC":"change_acl","WRITE_OWNER":"take_ownership"}

class ACLNormalizationError(ValueError):pass

def normalize_nfsv4(lines, identities):
    """Parse strict nfs4_getfacl A/D:flags:principal:rights entries.
    Unsupported ACE types, inheritance flags and ambiguous rights are blocked.
    """
    result=[]
    for line in lines:
        parts=line.strip().split(":",3)
        if len(parts)!=4 or parts[0] not in ("A","D") or not parts[2] or not parts[3]:
            raise ACLNormalizationError("UNSUPPORTED_NFSV4_ACE")
        effect,flags,name,permissions=parts
        if any(c not in "fdin" for c in flags):raise ACLNormalizationError("UNSUPPORTED_NFSV4_FLAGS")
        # nfs4_getfacl permissions include numerous fine-grained semantics not mapped here.
        # Fail closed rather than silently dropping any unknown permission.
        if any(c not in NFS_RIGHTS for c in permissions):raise ACLNormalizationError("UNMAPPED_NFSV4_RIGHT")
        if name not in identities:raise ACLNormalizationError("UNMAPPED_PRINCIPAL")
        principal=identities[name]
        if not isinstance(principal,Principal):raise ACLNormalizationError("INVALID_PRINCIPAL")
        rights=tuple(dict.fromkeys(NFS_RIGHTS[c] for c in permissions))
        result.append(ACE(principal,"allow" if effect=="A" else "deny",rights,bool(flags)))
    if not result:raise ACLNormalizationError("EMPTY_ACL")
    return result

def normalize_smb(lines, identities):
    """Strict subset of smbcacls ACL:SID:ALLOWED|DENIED/flags/rights.
    Unknown bitmask and composite permissions are not silently translated.
    """
    result=[]
    for line in lines:
        m=re.fullmatch(r"ACL:(.+?):(ALLOWED|DENIED)/0x([0-9a-fA-F]+)/([A-Z_]+)",line.strip())
        if not m:raise ACLNormalizationError("UNSUPPORTED_SMB_ACE")
        name,effect,flags,permission=m.groups()
        if int(flags,16)!=0:raise ACLNormalizationError("UNSUPPORTED_SMB_FLAGS")
        if permission not in SMB_RIGHTS:raise ACLNormalizationError("UNMAPPED_SMB_RIGHT")
        if name not in identities:raise ACLNormalizationError("UNMAPPED_PRINCIPAL")
        principal=identities[name]
        if not isinstance(principal,Principal):raise ACLNormalizationError("INVALID_PRINCIPAL")
        result.append(ACE(principal,"allow" if effect=="ALLOWED" else "deny",(SMB_RIGHTS[permission],)))
    if not result:raise ACLNormalizationError("EMPTY_ACL")
    return result

def compare_canonical(source,target,mapping,*,source_protocol,target_protocol,identity_verified=False):
    if not isinstance(mapping,IdentityMap):raise ACLNormalizationError("INVALID_MAPPING")
    if not isinstance(source,list) or not isinstance(target,list) or not source or not target:
        raise ACLNormalizationError("INCOMPLETE_ACL")
    if not all(isinstance(x,ACE) for x in source+target):raise ACLNormalizationError("INVALID_ACE")
    comparison=compare_acl(source,target,mapping,source_complete=True,target_complete=True,identity_verified=identity_verified)
    matched=not comparison["missing_mappings"] and not comparison["differences"]
    payload={"source_protocol":source_protocol,"target_protocol":target_protocol,"source_count":len(source),"target_count":len(target),"differences":comparison["differences"],"missing_mappings":comparison["missing_mappings"]}
    return {"schema":"odmm.acl.canonical.v2009","author":"Abdelhalim Talbi","status":"CANONICAL_MATCH_UNVERIFIED" if matched else "BLOCKED","canonical_acl_equal":matched,"effective_access_verified":False,"cutover_authorized":False,"native_engine_modified":False,"evidence_sha256":hashlib.sha256(json.dumps(payload,sort_keys=True).encode()).hexdigest(),**payload}

def compare_collected(source_evidence,target_evidence,source_identities,target_identities,mapping,*,identity_verified=False):
    if any(not isinstance(e,dict) or e.get("status")!="COLLECTED_UNVERIFIED" for e in (source_evidence,target_evidence)):
        return {"status":"BLOCKED","reason":"MISSING_COLLECTED_EVIDENCE","cutover_authorized":False}
    parsers={"NFSV4":normalize_nfsv4,"SMB":normalize_smb}
    try:
        s=parsers[source_evidence["protocol"]](source_evidence["entries"],source_identities)
        t=parsers[target_evidence["protocol"]](target_evidence["entries"],target_identities)
        return compare_canonical(s,t,mapping,source_protocol=source_evidence["protocol"],target_protocol=target_evidence["protocol"],identity_verified=identity_verified)
    except (KeyError,TypeError,ACLNormalizationError) as exc:
        return {"status":"BLOCKED","reason":"UNSUPPORTED_OR_UNMAPPED_ACL","detail":str(exc),"cutover_authorized":False}
