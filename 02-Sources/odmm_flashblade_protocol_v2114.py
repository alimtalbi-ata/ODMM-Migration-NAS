"""Conservative ONTAP/FlashBlade NFS/SMB comparison. Author: Abdelhalim Talbi."""
from collections.abc import Mapping

FIELDS = {'NFS': ('client_rules', 'security_flavors', 'read_only', 'root_squash', 'nfs_version'),
          'SMB': ('share_path', 'access_rules', 'abe_enabled', 'encryption_required', 'continuously_available')}

def compare_protocol_configuration(ontap, flashblade, *, protocol, direction):
    """Read-only comparison. Unknown and conflicting evidence always blocks cutover."""
    if protocol not in FIELDS or direction not in ('NETAPP_TO_FLASHBLADE','FLASHBLADE_TO_NETAPP'):
        raise ValueError('UNSUPPORTED_PROTOCOL_OR_DIRECTION')
    if not isinstance(ontap, Mapping) or not isinstance(flashblade, Mapping):
        raise ValueError('INVALID_PROTOCOL_EVIDENCE')
    src, dst = (ontap,flashblade) if direction == 'NETAPP_TO_FLASHBLADE' else (flashblade,ontap)
    checks=[]; blockers=[]
    for key in FIELDS[protocol]:
        a,b=src.get(key),dst.get(key)
        known = a is not None and b is not None and type(a) is type(b)
        same = known and a == b
        checks.append({'field':key,'status':'MATCH' if same else ('DIFFERENT' if known else 'UNVERIFIED')})
        if not same: blockers.append(('MISMATCH_' if known else 'MISSING_')+key.upper())
    # Even an exact configuration match does not prove effective access or metadata fidelity.
    blockers.extend(('ACL_EFFECTIVE_ACCESS_NOT_VERIFIED','IDENTITY_MAPPING_NOT_VERIFIED',
                     'PROTOCOL_BEHAVIOR_NOT_VERIFIED','CUTOVER_FENCING_NOT_VERIFIED'))
    return {'schema':'odmm.flashblade.protocol.v2114','direction':direction,'protocol':protocol,
            'checks':checks,'blockers':sorted(set(blockers)),'status':'BLOCKED',
            'engine':'ODMM_NATIVE','cutover_authorized':False}

def build_readonly_report(ontap, flashblade, *, direction):
    if not isinstance(ontap,Mapping) or not isinstance(flashblade,Mapping):
        raise ValueError('INVALID_INVENTORY')
    return {'schema':'odmm.flashblade.report.v2114','direction':direction,
            'nfs':compare_protocol_configuration(ontap.get('nfs',{}),flashblade.get('nfs',{}),protocol='NFS',direction=direction),
            'smb':compare_protocol_configuration(ontap.get('smb',{}),flashblade.get('smb',{}),protocol='SMB',direction=direction),
            'cutover_authorized':False}
