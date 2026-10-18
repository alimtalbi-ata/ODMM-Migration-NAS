"""Dell OneFS (Isilon/PowerScale) read-only discovery and ONTAP pairing.
Author: Abdelhalim Talbi. API routes require firmware-specific validation.
"""
from collections.abc import Mapping
from dataclasses import dataclass
from urllib.parse import quote

@dataclass(frozen=True)
class OneFSInventory:
    endpoint: dict
    evidence: dict
    blockers: tuple
    warnings: tuple


def discover_onefs(fetch, *, access_zone, path, api_version='v16'):
    """Trusted authenticated GET-only fetch(path) -> mapping; no mutation.

    OneFS platform endpoints are version-sensitive; v16 is a caller-verified
    capability selection, NOT an assertion of universal firmware support.
    """
    if not callable(fetch) or api_version != 'v16':
        raise ValueError('UNQUALIFIED_ONEFS_API_VERSION')
    for item in (access_zone, path):
        if not isinstance(item, str) or not item.strip() or '\x00' in item or '?' in item or '#' in item:
            raise ValueError('INVALID_ONEFS_SCOPE')
    if not path.startswith('/ifs/') or '..' in path.split('/'):
        raise ValueError('INVALID_ONEFS_PATH')
    zone = quote(access_zone, safe='')
    routes = {
        'zones': '/platform/16/zones',
        'nfs': '/platform/16/protocols/nfs/exports',
        'smb': '/platform/16/protocols/smb/shares',
    }
    evidence = {}; blockers = []
    for key, route in routes.items():
        try:
            data = fetch(route)
            expected = {'zones':'zones','nfs':'exports','smb':'shares'}[key]
            if not isinstance(data, Mapping) or not isinstance(data.get(expected), list):
                raise ValueError('INVALID_ONEFS_RESPONSE')
            evidence[key] = dict(data)
        except Exception:
            blockers.append('ONEFS_' + key.upper() + '_DISCOVERY_UNAVAILABLE')
    zones = evidence.get('zones', {}).get('zones', [])
    matches = [z for z in zones if isinstance(z, Mapping) and z.get('name') == access_zone]
    if len(matches) != 1:
        blockers.append('ONEFS_ACCESS_ZONE_UNVERIFIED')
    nfs = [x for x in evidence.get('nfs', {}).get('exports', [])
           if isinstance(x, Mapping) and path in (x.get('paths') or [])]
    smb = [x for x in evidence.get('smb', {}).get('shares', [])
           if isinstance(x, Mapping) and (x.get('path') == path or x.get('zone') == access_zone)]
    # SMB zone-only matches are candidates, not proof that a share maps to path.
    if any(x.get('path') != path for x in smb):
        blockers.append('ONEFS_SMB_NAMESPACE_AMBIGUOUS')
    protocols = tuple(p for p, items in (('NFS', nfs), ('SMB', smb)) if items)
    if len(protocols) != 1:
        blockers.append('ONEFS_PROTOCOL_SELECTION_REQUIRED')
    endpoint = {'vendor':'onefs', 'namespace':path, 'access_zone':access_zone,
                'protocol':'UNVERIFIED', 'identity_domain':'UNVERIFIED',
                'acl_model':'UNVERIFIED', 'capacity_free_bytes':None,
                'discovered_protocols':protocols, 'features':[]}
    return OneFSInventory(endpoint, evidence, tuple(sorted(set(blockers))),
                          ('ACL_IDENTITY_CAPACITY_AND_SNAPSHOT_SEMANTICS_REQUIRE_PROOFS',))


def compare_onefs_ontap(ontap, onefs, *, direction):
    if direction not in ('ONEFS_TO_NETAPP','NETAPP_TO_ONEFS'):
        raise ValueError('INVALID_DIRECTION')
    if not isinstance(ontap, Mapping) or not isinstance(onefs, OneFSInventory):
        raise ValueError('TRUSTED_INVENTORIES_REQUIRED')
    ns = ontap.get('namespace_id')
    blockers = list(onefs.blockers)
    if not isinstance(ns, str) or not ns.strip():
        blockers.append('ONTAP_NAMESPACE_UNVERIFIED')
    blockers.extend(('ACL_FIDELITY_UNVERIFIED','EFFECTIVE_ACCESS_UNVERIFIED',
                     'AD_LDAP_UID_GID_MAPPING_UNVERIFIED','INCREMENTAL_DELTA_UNVERIFIED',
                     'SNAPSHOT_AND_QUOTA_TRANSLATION_UNVERIFIED',
                     'FENCING_AND_ROLLBACK_UNVERIFIED','NATIVE_COPY_UNQUALIFIED'))
    source, target = ((onefs.endpoint['namespace'], ns) if direction == 'ONEFS_TO_NETAPP'
                      else (ns, onefs.endpoint['namespace']))
    return {'schema':'odmm.onefs.ontap.v2116','direction':direction,
            'source_namespace':source,'target_namespace':target,
            'protocol_candidates':onefs.endpoint['discovered_protocols'],
            'blockers':sorted(set(blockers)), 'status':'BLOCKED',
            'engine':'ODMM_NATIVE','cutover_authorized':False}
