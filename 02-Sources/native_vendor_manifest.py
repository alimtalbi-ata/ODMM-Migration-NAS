"""Signed, deployment-pinned vendor contracts. HMAC is for trusted shared-key deployments."""
import hashlib
import hmac
import json
from native_vendor_contracts import ContractRejected


def _canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=True, allow_nan=False).encode('ascii')


def seal_manifest(*, contracts, key, key_id):
    if not isinstance(contracts, dict) or not contracts or not isinstance(key, bytes) or len(key) < 32:
        raise ContractRejected('MANIFEST_INPUT_INVALID')
    if not isinstance(key_id, str) or not key_id or len(key_id) > 64:
        raise ContractRejected('MANIFEST_KEY_ID_INVALID')
    body = {'schema': 1, 'key_id': key_id, 'contracts': contracts}
    mac = hmac.new(key, _canonical(body), hashlib.sha256).hexdigest()
    return {**body, 'mac': mac}


def verify_manifest(*, manifest, pinned_keys):
    if not isinstance(manifest, dict) or set(manifest) != {'schema','key_id','contracts','mac'} or type(manifest['schema']) is not int or manifest['schema'] != 1:
        raise ContractRejected('MANIFEST_INVALID')
    kid = manifest['key_id']
    if not isinstance(kid, str) or not isinstance(pinned_keys, dict) or kid not in pinned_keys:
        raise ContractRejected('MANIFEST_KEY_UNTRUSTED')
    key = pinned_keys[kid]
    if not isinstance(key, bytes) or len(key) < 32:
        raise ContractRejected('MANIFEST_KEY_UNTRUSTED')
    mac = manifest['mac']
    if not isinstance(mac, str) or len(mac) != 64:
        raise ContractRejected('MANIFEST_SIGNATURE_INVALID')
    try:
        body = {k: manifest[k] for k in ('schema','key_id','contracts')}
        expected = hmac.new(key, _canonical(body), hashlib.sha256).hexdigest()
    except (ValueError, TypeError, OverflowError) as exc:
        raise ContractRejected('MANIFEST_INVALID') from exc
    if not hmac.compare_digest(expected, mac):
        raise ContractRejected('MANIFEST_SIGNATURE_INVALID')
    contracts = manifest['contracts']
    if not isinstance(contracts, dict) or not contracts:
        raise ContractRejected('MANIFEST_CONTRACTS_INVALID')
    for vendor, spec in contracts.items():
        if not isinstance(vendor, str) or not isinstance(spec, dict) or set(spec) != {'firmware','asset_field','state_field'}:
            raise ContractRejected('MANIFEST_CONTRACTS_INVALID')
    return json.loads(_canonical(contracts))
