"""V195.9 vendor observation adapter: fixed read-only endpoints and fail-closed parsing.

Transport is deployment-supplied and must enforce TLS verification, credential isolation,
network egress allowlisting and timeouts. No vendor hardware is contacted here.
"""
import hashlib
import json
import re
from urllib.parse import quote

_ASSET = re.compile(r'[A-Za-z0-9_.:-]{1,128}\Z')
VENDORS = {
    'netapp_ontap': ('/api/storage/volumes/{asset}', 'state'),
    'dell_powerscale': ('/platform/3/namespace/exports/{asset}', 'state'),
    'pure_flasharray': ('/api/2.0/volumes/{asset}', 'status'),
}


def make_readonly_collector(*, vendor, transport, trusted_origin, auth_provider, state_mapper, approved_contracts=None, production=False, signed_manifest=None, pinned_manifest_keys=None):
    """Build observer(asset_id) compatible with verify_external_state.

    transport(url, headers) -> (status:int, response_bytes:bytes). Transport MUST
    only use GET and never follow redirects; auth_provider is deployment-owned.
    state_mapper(vendor, payload) -> canonical state string. No automatic retries.
    """
    if type(production) is not bool:
        raise ValueError('PRODUCTION_FLAG_INVALID')
    if production:
        if approved_contracts is not None or signed_manifest is None or pinned_manifest_keys is None:
            raise ValueError('PRODUCTION_SIGNED_MANIFEST_REQUIRED')
        from native_vendor_manifest import verify_manifest
        approved_contracts = verify_manifest(manifest=signed_manifest, pinned_keys=pinned_manifest_keys)
    if vendor not in VENDORS:
        raise ValueError('VENDOR_UNSUPPORTED')
    if not isinstance(trusted_origin, str) or not trusted_origin.startswith('https://') or '/' in trusted_origin[8:] or '@' in trusted_origin:
        raise ValueError('VENDOR_ORIGIN_INVALID')
    if not all(callable(x) for x in (transport, auth_provider, state_mapper)):
        raise ValueError('VENDOR_TRUSTED_PROVIDERS_REQUIRED')
    path, _ = VENDORS[vendor]

    def observe(asset_id):
        if not isinstance(asset_id, str) or not _ASSET.fullmatch(asset_id):
            raise ValueError('VENDOR_ASSET_INVALID')
        url = trusted_origin + path.format(asset=quote(asset_id, safe=''))
        token = auth_provider(vendor)
        if not isinstance(token, str) or not token or '\n' in token or '\r' in token:
            raise ValueError('VENDOR_CREDENTIAL_INVALID')
        status, raw = transport(url, {'Authorization': 'Bearer ' + token, 'Accept': 'application/json'})
        if status != 200 or not isinstance(raw, bytes) or len(raw) > 65536:
            raise ValueError('VENDOR_READ_FAILED')
        try:
            payload = json.loads(raw)
        except (ValueError, UnicodeError) as exc:
            raise ValueError('VENDOR_RESPONSE_INVALID') from exc
        if not isinstance(payload, dict):
            raise ValueError('VENDOR_RESPONSE_INVALID')
        if approved_contracts is not None:
            from native_vendor_contracts import validate_vendor_observation
            state = validate_vendor_observation(vendor=vendor, payload=payload, asset_id=asset_id, approved_contracts=approved_contracts)
        else:
            state = state_mapper(vendor, payload)
        if not isinstance(state, str) or not state or len(state) > 256:
            raise ValueError('VENDOR_STATE_INVALID')
        return {'asset_id': asset_id, 'state': state, 'source': vendor + ':' + trusted_origin,
                'observed_at': str(payload.get('observed_at', 'unverified_vendor_timestamp')),
                'evidence': {'sha256': hashlib.sha256(raw).hexdigest(), 'vendor': vendor}}
    return observe
