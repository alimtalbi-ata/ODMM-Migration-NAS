"""V196.4 strict, opt-in vendor response contracts.

Contracts are explicit deployment-approved profiles, not assertions of vendor API
compatibility. Reject unknown firmware, unknown fields, booleans as numeric values,
and ambiguous state values. No mutation or network access.
"""
import re

class ContractRejected(ValueError):
    pass

_ID = re.compile(r'[A-Za-z0-9_.:-]{1,128}\Z')
_VERSION = re.compile(r'[A-Za-z0-9][A-Za-z0-9_.+-]{0,63}\Z')
_ALLOWED = frozenset({'ready','online','offline','degraded','unknown'})


def validate_vendor_observation(*, vendor, payload, asset_id, approved_contracts):
    if not isinstance(approved_contracts, dict) or not approved_contracts:
        raise ContractRejected('CONTRACT_REGISTRY_REQUIRED')
    if not isinstance(payload, dict) or not isinstance(asset_id, str) or not _ID.fullmatch(asset_id):
        raise ContractRejected('PAYLOAD_INVALID')
    if not isinstance(vendor, str) or vendor not in approved_contracts:
        raise ContractRejected('VENDOR_NOT_APPROVED')
    contract = approved_contracts[vendor]
    if not isinstance(contract, dict) or set(contract) != {'firmware', 'asset_field', 'state_field'}:
        raise ContractRejected('CONTRACT_INVALID')
    firmware, asset_field, state_field = (contract[k] for k in ('firmware','asset_field','state_field'))
    if not isinstance(firmware, str) or not _VERSION.fullmatch(firmware):
        raise ContractRejected('CONTRACT_INVALID')
    if not all(isinstance(k,str) and k.isidentifier() for k in (asset_field,state_field)):
        raise ContractRejected('CONTRACT_INVALID')
    if len({asset_field,state_field,'firmware'}) != 3:
        raise ContractRejected('CONTRACT_INVALID')
    if set(payload) != {asset_field,state_field,'firmware'}:
        raise ContractRejected('RESPONSE_FIELDS_MISMATCH')
    if type(payload['firmware']) is not str or payload['firmware'] != firmware:
        raise ContractRejected('FIRMWARE_UNAPPROVED')
    if type(payload[asset_field]) is not str or payload[asset_field] != asset_id:
        raise ContractRejected('ASSET_MISMATCH')
    state = payload[state_field]
    if type(state) is not str or state not in _ALLOWED:
        raise ContractRejected('STATE_UNAPPROVED')
    return state
