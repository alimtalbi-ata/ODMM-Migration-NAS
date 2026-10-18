"""Conservative source/target ACL and metadata fidelity checks. No cutover authorization.
Author: Abdelhalim Talbi.
"""
import hashlib
import json

ACL_KINDS={'NTFS','NFS4','POSIX','SMB_SHARE'}
FIELDS=('owner','group','acl_kind','acl','xattrs','ads','inheritance')

def _digest(value):
    return hashlib.sha256(json.dumps(value,sort_keys=True,separators=(',',':'),ensure_ascii=False).encode()).hexdigest()

def assess_fidelity(source, target, identity_mappings):
    """Compare *supplied* signed/attested observations, never infer effective access.

    Records require path, owner, group, acl_kind, acl (ordered ACEs), xattrs,
    ads, inheritance, evidence_id, evidence_sha256. Evidence hashes are of
    the canonical object without evidence_sha256. They provide integrity, not
    authentication: collectors must separately authenticate the origin.
    """
    blockers=[]; differences=[]; details=[]
    mapping={}; reverse={}
    for m in identity_mappings:
        if not isinstance(m,dict) or not all(isinstance(m.get(k),str) and m[k] for k in ('kind','source','target')):
            blockers.append('IDENTITY_MAPPING_INVALID');continue
        key=(m['kind'],m['source']); dest=(m['kind'],m['target'])
        if key in mapping and mapping[key]!=m['target']:blockers.append('IDENTITY_MAPPING_CONFLICT')
        if dest in reverse and reverse[dest]!=m['source']:blockers.append('IDENTITY_MAPPING_COLLISION')
        mapping[key]=m['target'];reverse[dest]=m['source']
    def parse(rows,side):
        result={}
        if not isinstance(rows,list) or not rows:blockers.append(side+'_FIDELITY_PROOFS_MISSING');return result
        for record in rows:
            if not isinstance(record,dict) or not all(k in record for k in FIELDS+('path','evidence_id','evidence_sha256')):
                blockers.append(side+'_FIDELITY_PROOF_INCOMPLETE');continue
            if (not isinstance(record['path'],str) or not record['path'].startswith('/') or
                record['acl_kind'] not in ACL_KINDS or not isinstance(record['acl'],list) or
                not isinstance(record['xattrs'],dict) or not isinstance(record['ads'],dict) or
                type(record['inheritance']) is not bool or
                not all(isinstance(record[k],str) and record[k] for k in ('owner','group','evidence_id'))):
                blockers.append(side+'_FIDELITY_PROOF_INVALID');continue
            supplied=record['evidence_sha256']
            if not isinstance(supplied,str) or supplied!=_digest({k:v for k,v in record.items() if k!='evidence_sha256'}):
                blockers.append(side+'_FIDELITY_HASH_INVALID');continue
            key=(record['path'],record['acl_kind'])
            if key in result:blockers.append(side+'_FIDELITY_DUPLICATE');continue
            result[key]=record
        return result
    src=parse(source,'SOURCE');dst=parse(target,'TARGET')
    for key,s in src.items():
        t=dst.get(key)
        if t is None:blockers.append('TARGET_FIDELITY_PROOF_MISSING');continue
        for field in FIELDS:
            sv=s[field];tv=t[field]
            if field in ('owner','group'):
                mapped=mapping.get((field.upper(),sv)) or mapping.get(('SID',sv)) or mapping.get(('UID',sv)) or mapping.get(('GID',sv))
                if mapped is None:blockers.append('IDENTITY_MAPPING_MISSING');continue
                sv=mapped
            if sv!=tv:
                blockers.append('FIDELITY_'+field.upper()+'_DRIFT')
                differences.append({'path':key[0],'acl_kind':key[1],'field':field,'source_digest':_digest(sv),'target_digest':_digest(tv),'source_evidence':s['evidence_id'],'target_evidence':t['evidence_id']})
        details.append({'path':key[0],'acl_kind':key[1],'source_evidence':s['evidence_id'],'target_evidence':t['evidence_id']})
    if set(dst)-set(src):blockers.append('UNEXPECTED_TARGET_FIDELITY_PROOF')
    return {'schema':'odmm.netapp.fidelity.v2087','status':'BLOCKED','cutover_authorized':False,'blockers':sorted(set(blockers)),'differences':differences,'proofs_compared':len(details),'proof_pairs':details,'warning':'Evidence SHA256 checks integrity only; source authentication and live effective-access testing remain mandatory.'}


def stamp_evidence(record):
    """Helper for synthetic tests/collector output; NOT an attestation signature."""
    return {**record,'evidence_sha256':_digest(record)}
