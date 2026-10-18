"""Read-only OneFS/FlashBlade bidirectional qualification. Author: Abdelhalim Talbi."""
from collections.abc import Mapping
from odmm_onefs_discovery_v2116 import OneFSInventory

DIRECTIONS = ('ONEFS_TO_FLASHBLADE', 'FLASHBLADE_TO_ONEFS')


def compare_onefs_flashblade(onefs, flashblade, *, direction):
    if direction not in DIRECTIONS:
        raise ValueError('UNSUPPORTED_DIRECTION')
    if not isinstance(onefs, OneFSInventory) or not isinstance(flashblade, Mapping):
        raise ValueError('TRUSTED_INVENTORIES_REQUIRED')
    ns = flashblade.get('namespace_id')
    blockers = list(onefs.blockers)
    if not isinstance(ns, str) or not ns.strip():
        blockers.append('FLASHBLADE_NAMESPACE_UNVERIFIED')
    for field in ('protocol', 'identity_domain', 'acl_model'):
        a, b = onefs.endpoint.get(field), flashblade.get(field)
        if not isinstance(a, str) or not isinstance(b, str) or a == 'UNVERIFIED' or b == 'UNVERIFIED':
            blockers.append('UNVERIFIED_' + field.upper())
        elif a != b:
            blockers.append('MISMATCH_' + field.upper())
    blockers.extend(('ACL_FIDELITY_UNVERIFIED', 'EFFECTIVE_ACCESS_UNVERIFIED',
                     'AD_LDAP_UID_GID_MAPPING_UNVERIFIED', 'METADATA_FIDELITY_UNVERIFIED',
                     'INCREMENTAL_DELTA_UNVERIFIED', 'FENCING_AND_ROLLBACK_UNVERIFIED',
                     'NATIVE_COPY_UNQUALIFIED'))
    source, target = ((onefs.endpoint['namespace'], ns) if direction == DIRECTIONS[0]
                      else (ns, onefs.endpoint['namespace']))
    return {'schema': 'odmm.onefs.flashblade.v2118', 'direction': direction,
            'source_namespace': source, 'target_namespace': target,
            'protocol_candidates': list(onefs.endpoint['discovered_protocols']),
            'blockers': sorted(set(blockers)), 'status': 'BLOCKED',
            'engine': 'ODMM_NATIVE', 'cutover_authorized': False}


def attach_onefs_flashblade_operations(app, *, authorize, get_flashblade_inventory,
                                         onefs_fetch, access_zone, path,
                                         api_version='v16', approved_versions=()):
    from fastapi import Request
    from fastapi.responses import JSONResponse
    from odmm_onefs_discovery_v2116 import discover_onefs
    from odmm_onefs_operations_v2117 import qualify_onefs_api
    if not all(callable(f) for f in (authorize, get_flashblade_inventory, onefs_fetch)):
        raise ValueError('TRUSTED_PROVIDERS_REQUIRED')
    headers = {'Cache-Control': 'no-store', 'X-Content-Type-Options': 'nosniff'}

    @app.get('/api/v1/operations/onefs-flashblade/compare/{direction}')
    def compare(request: Request, direction: str):
        try:
            permitted = authorize(request) is True
        except Exception:
            permitted = False
        if not permitted:
            return JSONResponse({'error': 'ACCESS_DENIED'}, status_code=403, headers=headers)
        if direction not in DIRECTIONS:
            return JSONResponse({'error': 'UNSUPPORTED_DIRECTION'}, status_code=400, headers=headers)
        try:
            qualify_onefs_api(onefs_fetch, version=api_version, approved_versions=approved_versions)
            blade = get_flashblade_inventory()
            if not isinstance(blade, Mapping):
                raise ValueError('INVALID_FLASHBLADE_INVENTORY')
            onefs = discover_onefs(onefs_fetch, access_zone=access_zone, path=path, api_version=api_version)
            result = compare_onefs_flashblade(onefs, blade, direction=direction)
        except Exception:
            return JSONResponse({'error': 'EVIDENCE_UNAVAILABLE', 'cutover_authorized': False},
                                status_code=503, headers=headers)
        return JSONResponse(result, headers=headers)
    return app
