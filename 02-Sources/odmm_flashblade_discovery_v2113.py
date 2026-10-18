"""Read-only FlashBlade discovery and conservative ONTAP/FlashBlade mapping.
Author: Abdelhalim Talbi. Transport and API version supplied by caller.
"""
from dataclasses import dataclass
from typing import Mapping

@dataclass(frozen=True)
class FlashBladeInventory:
    endpoint: dict
    evidence: dict
    blockers: tuple
    warnings: tuple


def discover_flashblade(fetch, *, filesystem_name, api_version='2.x'):
    """Use a trusted authenticated fetch(path)->dict. Never sends write requests.

    API routes reflect FlashBlade REST 2.x resource families; field-level and
    firmware compatibility must be validated against the deployed OpenAPI spec.
    """
    if not callable(fetch) or not isinstance(filesystem_name,str) or not filesystem_name.strip() or any(c in filesystem_name for c in '/?#'):
        raise ValueError('INVALID_FLASHBLADE_DISCOVERY_ARGUMENTS')
    if api_version != '2.x':
        raise ValueError('UNQUALIFIED_FLASHBLADE_API_VERSION')
    from urllib.parse import quote
    name=quote(filesystem_name,safe='')
    paths={'filesystem':f'/api/2.0/file-systems?names={name}',
           'nfs':f'/api/2.0/file-system-exports?file_system_names={name}',
           'smb':f'/api/2.0/smb-shares?file_system_names={name}'}
    evidence={}; blockers=[]
    for kind,path in paths.items():
        try:
            result=fetch(path)
            if not isinstance(result,Mapping) or not isinstance(result.get('items'),list):
                raise ValueError('INVALID_RESPONSE')
            evidence[kind]=dict(result)
        except Exception:
            blockers.append('FLASHBLADE_'+kind.upper()+'_DISCOVERY_UNAVAILABLE')
    files=evidence.get('filesystem',{}).get('items',[])
    matched=[f for f in files if isinstance(f,Mapping) and f.get('name')==filesystem_name]
    if len(matched)!=1:
        blockers.append('FLASHBLADE_FILESYSTEM_IDENTITY_UNVERIFIED')
    fs=matched[0] if len(matched)==1 else {}
    nfs=evidence.get('nfs',{}).get('items',[])
    smb=evidence.get('smb',{}).get('items',[])
    protocols=tuple(k for k,items in (('NFS',nfs),('SMB',smb)) if items)
    if len(protocols)!=1:
        blockers.append('FLASHBLADE_PROTOCOL_SELECTION_REQUIRED')
    endpoint={'vendor':'flashblade','namespace':filesystem_name,
              'protocol':'UNVERIFIED', 'identity_domain':'UNVERIFIED',
              'acl_model':'UNVERIFIED', 'capacity_free_bytes':None,
              'features':[], 'discovered_protocols':protocols,
              'filesystem_id':fs.get('id')}
    return FlashBladeInventory(endpoint,evidence,tuple(sorted(set(blockers))),
                               ('ACL_IDENTITY_AND_CAPACITY_REQUIRE_INDEPENDENT_PROOFS',))


def compare_nas_namespaces(ontap:Mapping, flashblade:FlashBladeInventory, *, direction:str):
    """Mapping proposal only; never infers protocol/ACL fidelity or permits cutover."""
    if direction not in ('NETAPP_TO_FLASHBLADE','FLASHBLADE_TO_NETAPP'):
        raise ValueError('INVALID_DIRECTION')
    if not isinstance(ontap,Mapping) or not isinstance(flashblade,FlashBladeInventory):
        raise ValueError('INVENTORY_REQUIRED')
    src=ontap.get('namespace_id')
    dst=flashblade.endpoint['namespace']
    blockers=list(flashblade.blockers)
    if not isinstance(src,str) or not src.strip():
        blockers.append('NETAPP_NAMESPACE_UNVERIFIED')
    blockers += ['ACL_FIDELITY_UNVERIFIED','EFFECTIVE_ACCESS_UNVERIFIED',
                 'IDENTITY_MAPPING_UNVERIFIED','INCREMENTAL_SYNC_UNVERIFIED',
                 'FENCING_AND_ROLLBACK_UNVERIFIED']
    return {'schema':'odmm.netapp.flashblade.mapping.v2113', 'direction':direction,
            'source_namespace':src if direction=='NETAPP_TO_FLASHBLADE' else dst,
            'target_namespace':dst if direction=='NETAPP_TO_FLASHBLADE' else src,
            'protocol_candidates':flashblade.endpoint['discovered_protocols'],
            'blockers':sorted(set(blockers)), 'status':'BLOCKED',
            'engine':'ODMM_NATIVE','cutover_authorized':False}
