"""Read-only NAS source/target planning matrix. Author: Abdelhalim Talbi.

No compatibility certification, real API collection, copy, or cutover.
"""
from dataclasses import dataclass, asdict
from collections.abc import Mapping

VENDORS = {
    'netapp_ontap': ('netapp', 'ontap', 'fas', 'aff'),
    'pure_flashblade': ('flashblade', 'pure', 'pure_storage'),
    'dell_onefs': ('onefs', 'isilon', 'powerscale'),
    'dell_unity': ('unity', 'dell_unity'),
    'dell_powerstore': ('powerstore', 'dell_powerstore'),
    'dell_powermax': ('powermax', 'dell_powermax'),
    'ibm_storage_scale': ('ibm_storage_scale', 'spectrum_scale', 'gpfs'),
    'ibm_flashsystem': ('ibm_flashsystem', 'flashsystem'),
    'hpe_alletra': ('hpe_alletra', 'alletra'),
    'hitachi_vantara': ('hitachi', 'hitachi_vantara', 'hcs'),
    'synology_dsm': ('synology', 'dsm'),
    'qnap_qts': ('qnap', 'qts', 'quTS'),
    'truenas': ('truenas', 'truenas_scale', 'truenas_core'),
    'generic_posix': ('generic_posix', 'linux_nfs', 'samba'),
    'windows_fileserver': ('windows_fileserver', 'windows_smb'),
}
ALIASES = {alias.casefold(): vendor for vendor, aliases in VENDORS.items() for alias in (vendor, *aliases)}
PROTOCOLS = frozenset(('NFS3','NFS4','SMB2','SMB3'))
PROOFS = ('source_inventory','target_inventory','source_acl','target_acl',
          'identity_mapping','effective_access','metadata_fidelity','native_copy',
          'delta_consistency','rollback','distributed_fencing')

@dataclass(frozen=True)
class PairPlan:
    source: str
    target: str
    direction: str
    source_protocol: str
    target_protocol: str
    blockers: tuple[str,...]
    required_proofs: tuple[str,...] = PROOFS
    status: str = 'BLOCKED'
    engine: str = 'ODMM_NATIVE'
    cutover_authorized: bool = False
    acl_fidelity_verified: bool = False

def normalize_vendor(value):
    if not isinstance(value,str) or not value.strip():
        raise ValueError('VENDOR_REQUIRED')
    vendor = ALIASES.get(value.strip().casefold())
    if vendor is None:
        raise ValueError('UNRECOGNIZED_VENDOR')
    return vendor

def plan_pair(source, target):
    """Build conservative read-only assessment of a requested migration pair."""
    if not isinstance(source, Mapping) or not isinstance(target, Mapping):
        raise ValueError('ENDPOINTS_REQUIRED')
    sv, tv = normalize_vendor(source.get('vendor')), normalize_vendor(target.get('vendor'))
    sp, tp = source.get('protocol'), target.get('protocol')
    blockers = ['CUTOVER_NOT_AUTHORIZED','VENDOR_API_NOT_QUALIFIED',
                'NATIVE_COPY_NOT_QUALIFIED','DISTRIBUTED_FENCING_NOT_VERIFIED',
                'ACL_FIDELITY_NOT_VERIFIED','EFFECTIVE_ACCESS_NOT_VERIFIED',
                'IDENTITY_MAPPING_NOT_VERIFIED','ROLLBACK_NOT_VERIFIED']
    if sv == tv: blockers.append('SAME_VENDOR_PAIR_REQUIRES_EXPLICIT_QUALIFICATION')
    if sp not in PROTOCOLS or tp not in PROTOCOLS:
        blockers.append('PROTOCOL_UNVERIFIED')
    elif sp != tp:
        blockers.append('PROTOCOL_TRANSLATION_NOT_QUALIFIED')
    for side, endpoint in (('SOURCE',source),('TARGET',target)):
        if endpoint.get('inventory_complete') is not True:
            blockers.append(side+'_INVENTORY_INCOMPLETE')
        if not isinstance(endpoint.get('namespace'),str) or not endpoint['namespace'].strip():
            blockers.append(side+'_NAMESPACE_MISSING')
    return PairPlan(sv,tv,sv.upper()+'_TO_'+tv.upper(),
                    str(sp or 'UNVERIFIED'),str(tp or 'UNVERIFIED'),tuple(sorted(set(blockers))))

def matrix(*, include_same_vendor=False, protocol='SMB3'):
    """Return every ordered combination; never interpret as certified support."""
    if protocol not in PROTOCOLS: raise ValueError('PROTOCOL_UNVERIFIED')
    return tuple(plan_pair({'vendor':s,'protocol':protocol,'namespace':'/source','inventory_complete':False},
                           {'vendor':t,'protocol':protocol,'namespace':'/target','inventory_complete':False})
                 for s in VENDORS for t in VENDORS if include_same_vendor or s != t)

def matrix_report(*, include_same_vendor=False, protocol='SMB3'):
    plans = matrix(include_same_vendor=include_same_vendor,protocol=protocol)
    return {'count':len(plans),'vendor_count':len(VENDORS),
            'certified_pairs':0,'cutover_authorized':False,
            'plans':[asdict(plan) for plan in plans]}
