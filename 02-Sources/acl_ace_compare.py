"""Offline structural ACE comparison, NOT effective-rights equivalence."""
import hashlib
import json

class ACEComparisonError(ValueError): pass

def _hash(value):
    return hashlib.sha256(json.dumps(value,sort_keys=True,separators=(",",":"),ensure_ascii=True,allow_nan=False).encode()).hexdigest()

def _normalize(aces):
    if not isinstance(aces,list) or len(aces)>10000:
        raise ACEComparisonError('INVALID_ACES')
    output=[]
    for ace in aces:
        if not isinstance(ace,dict) or set(ace)!={'principal','type','rights','flags','inherited'}:
            raise ACEComparisonError('INVALID_ACE_SCHEMA')
        principal=ace['principal']
        if not isinstance(principal,str) or not principal or len(principal)>256:
            raise ACEComparisonError('INVALID_PRINCIPAL')
        if ace['type'] not in ('ALLOW','DENY') or type(ace['inherited']) is not bool:
            raise ACEComparisonError('INVALID_ACE_TYPE')
        rights=ace['rights']; flags=ace['flags']
        if not isinstance(rights,list) or not isinstance(flags,list):
            raise ACEComparisonError('INVALID_RIGHTS_FLAGS')
        if any(not isinstance(x,str) or not x or len(x)>64 for x in rights+flags):
            raise ACEComparisonError('INVALID_RIGHTS_FLAGS')
        if len(set(rights))!=len(rights) or len(set(flags))!=len(flags) or len(rights)>64 or len(flags)>64:
            raise ACEComparisonError('DUPLICATE_OR_EXCESSIVE_FLAGS')
        output.append({'principal':principal,'type':ace['type'],'rights':sorted(rights),
                       'flags':sorted(flags),'inherited':ace['inherited']})
    return output

def compare_ace_snapshots(source,target,*,protocol):
    if protocol not in ('NFSv4','SMB'):
        raise ACEComparisonError('UNSUPPORTED_PROTOCOL')
    left=_normalize(source); right=_normalize(target)
    # ACE order matters for access checks. Do not sort ACE sequences.
    changed=[i for i in range(max(len(left),len(right)))
             if i>=len(left) or i>=len(right) or left[i]!=right[i]]
    status='STRUCTURAL_MATCH_ONLY' if not changed else 'BLOCKED_ACE_DRIFT'
    report={'schema':'odmm.ace-compare.v1','protocol':protocol,'status':status,
            'source_count':len(left),'target_count':len(right),'changed_positions':changed,
            'source_digest':_hash(left),'target_digest':_hash(right),
            'cutover_authorized':False,'production_qualified':False,'manual_review_required':True,
            'limitations':['OFFLINE_UNAUTHENTICATED_ACL_SNAPSHOTS','NO_IDENTITY_RESOLUTION',
                           'NO_NFS_SMB_SEMANTIC_EQUIVALENCE','NO_LIVE_EFFECTIVE_ACCESS_TEST']}
    return {'report':report,'sha256':_hash(report)}

def verify_ace_comparison(bundle,source,target,*,protocol):
    if not isinstance(bundle,dict) or bundle!=compare_ace_snapshots(source,target,protocol=protocol):
        raise ACEComparisonError('REPORT_MISMATCH')
    return True
