"""Offline directory snapshot cross-check; never authenticates a directory."""
import hashlib
import json
from identity_mapping_matrix import verify_mapping_matrix, _identity, MappingMatrixError

class DirectorySnapshotError(ValueError): pass

def _digest(report):
    return hashlib.sha256(json.dumps(report,sort_keys=True,separators=(',',':'),ensure_ascii=True).encode()).hexdigest()

def review_directory_snapshots(mapping_bundle, snapshots):
    try: verify_mapping_matrix(mapping_bundle)
    except (MappingMatrixError, TypeError, ValueError) as exc: raise DirectorySnapshotError('INVALID_MAPPING') from exc
    if not isinstance(snapshots,list): raise DirectorySnapshotError('INVALID_SNAPSHOTS')
    index={}
    for snap in snapshots:
        if not isinstance(snap,dict) or set(snap) != {'identity','snapshot_ref','groups'}:
            raise DirectorySnapshotError('INVALID_SNAPSHOT')
        try: key=_identity(snap['identity'])
        except (MappingMatrixError,TypeError) as exc: raise DirectorySnapshotError('INVALID_IDENTITY') from exc
        ref=snap['snapshot_ref']
        if not isinstance(ref,str) or not (1<=len(ref)<=128) or not all(c.isalnum() or c in '_.:-' for c in ref) or not ref.isascii():
            raise DirectorySnapshotError('INVALID_REF')
        groups=snap['groups']
        if not isinstance(groups,list) or len(groups)>1024: raise DirectorySnapshotError('INVALID_GROUPS')
        try: group_ids=[_identity(x) for x in groups]
        except (MappingMatrixError,TypeError) as exc: raise DirectorySnapshotError('INVALID_GROUP') from exc
        if any(g[2]!='group' for g in group_ids) or len(set(group_ids))!=len(group_ids):
            raise DirectorySnapshotError('INVALID_GROUP_MEMBERSHIP')
        if key in index: raise DirectorySnapshotError('DUPLICATE_SNAPSHOT')
        index[key]={'ref':ref,'groups':set(group_ids)}
    mapping=mapping_bundle['report']; findings=[]
    for entry in mapping['entries']:
        src=_identity(entry['source']); target=_identity(entry['target'])
        a=index.get(src); b=index.get(target)
        if not a or not b: status='MISSING_SNAPSHOT'
        elif src[2]=='user' and (a['groups'] or b['groups']): status='GROUP_MEMBERSHIP_UNVERIFIED'
        else: status='SNAPSHOTS_PRESENT_UNAUTHENTICATED'
        findings.append({'source':list(src),'target':list(target),'status':status,
                         'source_ref':a['ref'] if a else None,'target_ref':b['ref'] if b else None})
    findings.sort(key=lambda x:json.dumps(x,sort_keys=True))
    report={'schema':'odmm.directory-snapshot-review.v1','mapping_sha256':mapping_bundle['sha256'],
            'findings':findings,'status':'BLOCKED' if mapping['status']=='BLOCKED' else 'PENDING_LIVE_DIRECTORY_VERIFICATION',
            'directory_verified':False,'group_expansion_verified':False,'effective_access_verified':False,
            'production_qualified':False,'limitations':['OPERATOR_SUPPLIED_SNAPSHOTS','NO_DIRECTORY_AUTHENTICATION','NO_NESTED_GROUP_EXPANSION','NO_LIVE_ACCESS_TEST']}
    return {'report':report,'sha256':_digest(report)}

def verify_directory_snapshot_review(bundle,mapping_bundle,snapshots):
    if not isinstance(bundle,dict) or set(bundle)!={'report','sha256'}: raise DirectorySnapshotError('INVALID_BUNDLE')
    if bundle!=review_directory_snapshots(mapping_bundle,snapshots): raise DirectorySnapshotError('REPORT_MISMATCH')
    return True
