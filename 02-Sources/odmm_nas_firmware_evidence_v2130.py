"""Fail-closed, read-only vendor firmware capability evidence. Author: Abdelhalim Talbi.

This validates the shape and internal consistency of supplied evidence, NOT actual
firmware compatibility or manufacturer support. No network calls or writes.
"""
from dataclasses import dataclass
from collections.abc import Mapping
from datetime import datetime, timezone
from odmm_nas_pair_matrix_v2128 import normalize_vendor, PROTOCOLS

@dataclass(frozen=True)
class EndpointEvidence:
    vendor: str
    model: str
    firmware: str
    serial_ref: str
    protocols: tuple[str, ...]
    acl_models: tuple[str, ...]
    evidence_id: str
    collected_at: str
    collection_method: str
    warnings: tuple[str, ...]
    independently_certified: bool = False

@dataclass(frozen=True)
class PairEvidence:
    source: EndpointEvidence
    target: EndpointEvidence
    common_protocols: tuple[str, ...]
    common_acl_models: tuple[str, ...]
    blockers: tuple[str, ...]
    classification: str
    engine: str = 'ODMM_NATIVE'
    cutover_authorized: bool = False
    certified: bool = False

_ALLOWED_ACL = frozenset(('NFS4', 'POSIX', 'NTFS'))
_ALLOWED_METHODS = frozenset(('API_READONLY', 'CLI_READONLY', 'MANUAL', 'SIMULATOR'))

def _string(obj, key, *, limit=256):
    v = obj.get(key)
    if not isinstance(v, str) or not v.strip() or len(v) > limit or any(ord(c) < 32 for c in v):
        raise ValueError(key.upper()+'_INVALID')
    return v.strip()

def _names(obj, key, allowed):
    value = obj.get(key)
    if not isinstance(value, (list, tuple)) or not value or any(not isinstance(v,str) or v not in allowed for v in value):
        raise ValueError(key.upper()+'_INVALID')
    if len(value) != len(set(value)):
        raise ValueError(key.upper()+'_DUPLICATE')
    return tuple(sorted(value))

def inspect_endpoint(raw, *, expected_vendor=None):
    if not isinstance(raw, Mapping):
        raise ValueError('ENDPOINT_MAPPING_REQUIRED')
    vendor = normalize_vendor(raw.get('vendor'))
    if expected_vendor is not None and vendor != normalize_vendor(expected_vendor):
        raise ValueError('VENDOR_MISMATCH')
    model = _string(raw, 'model'); firmware = _string(raw, 'firmware')
    serial = _string(raw, 'serial_ref'); eid = _string(raw, 'evidence_id')
    method = _string(raw, 'collection_method')
    if method not in _ALLOWED_METHODS:
        raise ValueError('COLLECTION_METHOD_INVALID')
    stamp = _string(raw, 'collected_at')
    try:
        dt = datetime.fromisoformat(stamp.replace('Z','+00:00'))
    except ValueError as exc:
        raise ValueError('COLLECTION_TIME_INVALID') from exc
    if dt.tzinfo is None or dt.utcoffset() is None:
        raise ValueError('COLLECTION_TIME_NOT_TIMEZONED')
    protocols = _names(raw,'protocols',PROTOCOLS)
    acls = _names(raw,'acl_models',_ALLOWED_ACL)
    warnings=[]
    if method in ('MANUAL','SIMULATOR'):
        warnings.append('NOT_LIVE_APPLIANCE_DISCOVERY')
    if raw.get('pagination_complete') is not True:
        warnings.append('PAGINATION_NOT_VERIFIED')
    if raw.get('inventory_complete') is not True:
        warnings.append('INVENTORY_INCOMPLETE')
    if raw.get('read_only') is not True:
        warnings.append('READ_ONLY_COLLECTION_NOT_VERIFIED')
    if raw.get('vendor_api_qualified') is not True:
        warnings.append('VENDOR_API_FIRMWARE_NOT_QUALIFIED')
    if raw.get('acl_evidence_complete') is not True:
        warnings.append('ACL_EVIDENCE_INCOMPLETE')
    return EndpointEvidence(vendor,model,firmware,serial,protocols,acls,eid,dt.isoformat(),method,tuple(warnings))

def inspect_pair(source, target):
    s=inspect_endpoint(source); t=inspect_endpoint(target)
    common=tuple(sorted(set(s.protocols)&set(t.protocols)))
    acl=tuple(sorted(set(s.acl_models)&set(t.acl_models)))
    blockers=['NO_INDEPENDENT_HARDWARE_FIRMWARE_CERTIFICATION','CUTOVER_NOT_AUTHORIZED',
              'NATIVE_MIGRATION_NOT_END_TO_END_QUALIFIED','EFFECTIVE_ACCESS_NOT_VERIFIED',
              'DISTRIBUTED_FENCING_NOT_VERIFIED','ROLLBACK_NOT_VERIFIED']
    blockers.extend('SOURCE_'+w for w in s.warnings)
    blockers.extend('TARGET_'+w for w in t.warnings)
    if not common: blockers.append('NO_COMMON_PROTOCOL')
    if not acl: blockers.append('NO_COMMON_ACL_MODEL')
    if s.vendor == t.vendor: blockers.append('SAME_VENDOR_REQUIRES_QUALIFICATION')
    classification = 'CONDITIONAL' if common and acl and not s.warnings and not t.warnings else 'NOT_QUALIFIED'
    return PairEvidence(s,t,common,acl,tuple(sorted(set(blockers))),classification)
