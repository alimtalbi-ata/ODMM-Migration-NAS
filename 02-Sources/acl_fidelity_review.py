"""Fail-closed, offline ACL metadata fidelity review (no semantic equivalence)."""
import re
from native_acl_normalize import parse_nfs4, parse_smb, NativeACLParseError
from acl_ace_compare import compare_ace_snapshots, _hash

class ACLFidelityError(ValueError): pass

_SID = re.compile(r"S-1-(?:[0-9]+-)+[0-9]+\Z")

def _smb_envelope(text):
    if not isinstance(text, str) or len(text)>1000000:
        raise ACLFidelityError('INVALID_INPUT')
    metadata = {}
    ace_lines=[]
    for raw in text.splitlines():
        line=raw.strip()
        if not line: continue
        if line.startswith(('OWNER:', 'GROUP:', 'REVISION:')):
            key, value=line.split(':',1)
            if key in metadata: raise ACLFidelityError('DUPLICATE_METADATA')
            value=value.strip()
            if key in ('OWNER','GROUP') and not _SID.fullmatch(value):
                raise ACLFidelityError('UNSUPPORTED_IDENTITY')
            if key=='REVISION' and (not value.isdigit() or len(value)>3):
                raise ACLFidelityError('INVALID_REVISION')
            metadata[key]=value
        else:
            ace_lines.append(line)
    try: aces=parse_smb('\n'.join(ace_lines))
    except NativeACLParseError as exc: raise ACLFidelityError('UNSUPPORTED_ACL') from exc
    return metadata, aces

def review_acl_fidelity(source_text,target_text,*,protocol):
    if protocol=='SMB':
        source_meta,source_aces=_smb_envelope(source_text)
        target_meta,target_aces=_smb_envelope(target_text)
    elif protocol=='NFSv4':
        # NFS comment headers may contain owner/group information, but are not
        # parsed or attested here; explicitly report metadata as unverified.
        try:
            source_aces=parse_nfs4(source_text)
            target_aces=parse_nfs4(target_text)
        except NativeACLParseError as exc: raise ACLFidelityError('UNSUPPORTED_ACL') from exc
        source_meta=target_meta={}
    else: raise ACLFidelityError('UNSUPPORTED_PROTOCOL')
    comparison=compare_ace_snapshots(source_aces,target_aces,protocol=protocol)
    metadata_keys=sorted(set(source_meta)|set(target_meta))
    drift=[k for k in metadata_keys if source_meta.get(k)!=target_meta.get(k)]
    missing=[k for k in ('OWNER','GROUP','REVISION') if k not in source_meta or k not in target_meta] if protocol=='SMB' else ['NFS_OWNER','NFS_GROUP']
    if drift or comparison['report']['status']=='BLOCKED_ACE_DRIFT': status='BLOCKED_ACL_FIDELITY_DRIFT'
    elif missing: status='INDETERMINATE_METADATA'
    else: status='STRUCTURAL_MATCH_ONLY'
    report={'schema':'odmm.acl-fidelity.v1','protocol':protocol,'status':status,
            'ace_comparison_sha256':comparison['sha256'],
            'source_metadata_sha256':_hash(source_meta),'target_metadata_sha256':_hash(target_meta),
            'metadata_drift':drift,'missing_metadata':missing,
            'production_qualified':False,'cutover_authorized':False,
            'manual_review_required':True,
            'limitations':['OFFLINE_UNAUTHENTICATED_INPUT','STRICT_NATIVE_SUBSET_ONLY',
                           'NO_EFFECTIVE_ACCESS_EQUIVALENCE','NO_CROSS_PROTOCOL_TRANSLATION']}
    return {'report':report,'sha256':_hash(report)}

def verify_acl_fidelity(bundle,source_text,target_text,*,protocol):
    if bundle!=review_acl_fidelity(source_text,target_text,protocol=protocol):
        raise ACLFidelityError('REPORT_MISMATCH')
    return True
