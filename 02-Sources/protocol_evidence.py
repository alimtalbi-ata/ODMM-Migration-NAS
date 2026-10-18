"""Offline NFSv4/SMB ACL evidence ingestion. No NAS access or permissions claims."""
import hashlib, json

PROTOCOLS = {'NFSv4', 'SMB'}

def canonical_json(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=False).encode('utf-8')

def normalize_acl_capture(capture):
    """Validate externally supplied, opaque ACL evidence; fail closed."""
    if not isinstance(capture, dict):
        raise ValueError('capture must be object')
    required = {'protocol','side','path','collector','identity_context','acl_raw_sha256','complete'}
    if not required.issubset(capture):
        raise ValueError('missing required evidence')
    if capture['protocol'] not in PROTOCOLS or capture['side'] not in ('source','target'):
        raise ValueError('invalid protocol or side')
    for field in ('path','collector','identity_context'):
        if not isinstance(capture[field],str) or not capture[field].strip():
            raise ValueError('missing identity context')
    digest=capture['acl_raw_sha256']
    if not isinstance(digest,str) or len(digest)!=64 or any(c not in '0123456789abcdef' for c in digest):
        raise ValueError('invalid sha256')
    if type(capture['complete']) is not bool:
        raise ValueError('completeness must be boolean')
    normalized={k:capture[k] for k in sorted(required)}
    normalized['status']='CAPTURED_UNVERIFIED' if capture['complete'] else 'INCOMPLETE'
    normalized['effective_access_certified']=False
    normalized['evidence_sha256']=hashlib.sha256(canonical_json(normalized)).hexdigest()
    return normalized

def compare_captures(source,target):
    a,b=normalize_acl_capture(source),normalize_acl_capture(target)
    reasons=[]
    if a['side']!='source' or b['side']!='target': reasons.append('SIDE_MISMATCH')
    if a['protocol']!=b['protocol']: reasons.append('PROTOCOL_MISMATCH')
    if a['path']!=b['path']: reasons.append('PATH_MISMATCH')
    if not a['complete'] or not b['complete']: reasons.append('INCOMPLETE_CAPTURE')
    if a['acl_raw_sha256']!=b['acl_raw_sha256']: reasons.append('OPAQUE_ACL_DIFFERENCE')
    return {'status':'BLOCKED' if reasons else 'MATCHED_OPAQUE_EVIDENCE',
            'reasons':reasons,'effective_access_certified':False,
            'source_evidence_sha256':a['evidence_sha256'],
            'target_evidence_sha256':b['evidence_sha256'],
            'limitations':['NO_REMOTE_COLLECTION','NO_EFFECTIVE_ACCESS_PROBE','NO_IDENTITY_EQUIVALENCE_PROOF']}

def qualification_report(comparisons):
    entries=list(comparisons)
    if not all(isinstance(x,dict) and x.get('status') in ('BLOCKED','MATCHED_OPAQUE_EVIDENCE') for x in entries):
        raise ValueError('invalid comparisons')
    report={'schema':'odmm.protocol-evidence.v1','count':len(entries),
            'blocked':sum(x['status']=='BLOCKED' for x in entries),
            'status':'NOT_QUALIFIED','effective_access_certified':False,
            'results':entries}
    report['report_sha256']=hashlib.sha256(canonical_json(report)).hexdigest()
    return report
