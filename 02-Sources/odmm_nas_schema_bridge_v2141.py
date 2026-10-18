"""Fail-closed bridge from bounded vendor pages to a read-only qualification summary.
Author: Abdelhalim Talbi. Schema profiles are deployment inputs, not certifications.
"""
import hashlib
import json
from dataclasses import dataclass
from odmm_nas_qualified_reader_v2140 import Profile, collect_pages, VENDORS

@dataclass(frozen=True)
class SchemaContract:
    vendor: str
    required_fields: tuple
    id_field: str
    max_rows: int = 100000


def validate_inventory(*, collected, contract):
    if type(contract) is not SchemaContract or contract.vendor not in VENDORS:
        raise ValueError('INVALID_CONTRACT')
    if (type(contract.required_fields) is not tuple or not contract.required_fields or
        any(type(x) is not str or not x.isidentifier() for x in contract.required_fields) or
        len(set(contract.required_fields)) != len(contract.required_fields) or
        type(contract.id_field) is not str or contract.id_field not in contract.required_fields or
        type(contract.max_rows) is not int or not 1 <= contract.max_rows <= 100000):
        raise ValueError('INVALID_CONTRACT')
    if type(collected) is not dict or collected.get('vendor') != contract.vendor or collected.get('pagination_complete') is not True or collected.get('certified') is not False or collected.get('cutover_authorized') is not False:
        raise ValueError('UNTRUSTED_COLLECTION')
    rows = collected.get('records')
    if type(rows) is not list or len(rows) > contract.max_rows or collected.get('record_count') != len(rows):
        raise ValueError('INVALID_RECORD_COUNT')
    ids = set()
    for row in rows:
        if type(row) is not dict or not set(contract.required_fields).issubset(row):
            raise ValueError('SCHEMA_MISMATCH')
        identifier = row[contract.id_field]
        if type(identifier) is not str or not identifier or len(identifier) > 256 or any(ord(c) < 32 for c in identifier):
            raise ValueError('INVALID_IDENTIFIER')
        if identifier in ids: raise ValueError('DUPLICATE_IDENTIFIER')
        ids.add(identifier)
    payload = {'vendor':contract.vendor,'collection_digest':collected.get('digest'),
               'schema_fields':contract.required_fields,'identifiers':sorted(ids)}
    digest = hashlib.sha256(json.dumps(payload,sort_keys=True,separators=(',',':')).encode()).hexdigest()
    return {'vendor':contract.vendor,'record_count':len(rows),'schema_digest':digest,
            'collection_digest':collected.get('digest'), 'blockers':[
            'FIRMWARE_SCHEMA_NOT_INDEPENDENTLY_VERIFIED','IDENTITY_AND_ACL_NOT_PROVEN',
            'TRANSPORT_PROVENANCE_NOT_ATTESTED','CUTOVER_NOT_AUTHORIZED'],
            'certified':False,'cutover_authorized':False,'engine':'ODMM_NATIVE'}


def collect_and_validate(*,base_url,profile,transport,authorization,contract,**limits):
    if type(profile) is not Profile or type(contract) is not SchemaContract or profile.vendor != contract.vendor:
        raise ValueError('PROFILE_CONTRACT_MISMATCH')
    collected=collect_pages(base_url=base_url,profile=profile,transport=transport,authorization=authorization,**limits)
    return validate_inventory(collected=collected,contract=contract)
