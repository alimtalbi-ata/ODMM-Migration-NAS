"""Offline AD/LDAP/UID/GID/SID mapping review. Never asserts directory verification."""
import hashlib
import json
import re

class MappingMatrixError(ValueError): pass
KINDS = ('user', 'group')
SYSTEMS = ('AD', 'LDAP', 'POSIX')
IDENTIFIERS = {'AD': ('SID',), 'LDAP': ('DN', 'UID', 'GID'), 'POSIX': ('UID', 'GID')}

def _identity(item):
    if not isinstance(item, dict) or set(item) != {'system', 'realm', 'kind', 'id_type', 'identifier'}:
        raise MappingMatrixError('INVALID_IDENTITY')
    system, realm, kind, id_type, identifier = (item[k] for k in ('system','realm','kind','id_type','identifier'))
    if system not in SYSTEMS or kind not in KINDS or id_type not in IDENTIFIERS[system]:
        raise MappingMatrixError('INVALID_IDENTITY_TYPE')
    if not isinstance(realm,str) or not 1 <= len(realm) <= 128 or any(c in realm for c in '\x00\r\n'):
        raise MappingMatrixError('INVALID_REALM')
    if not isinstance(identifier,str) or not 1 <= len(identifier) <= 512 or any(c in identifier for c in '\x00\r\n'):
        raise MappingMatrixError('INVALID_IDENTIFIER')
    if id_type == 'SID' and not re.fullmatch(r'S-1-(?:[0-9]+-)+[0-9]+', identifier):
        raise MappingMatrixError('INVALID_SID')
    if id_type in ('UID','GID') and (not identifier.isascii() or not identifier.isdecimal() or int(identifier) > 4294967295):
        raise MappingMatrixError('INVALID_NUMERIC_ID')
    if id_type == 'UID' and kind != 'user' or id_type == 'GID' and kind != 'group':
        raise MappingMatrixError('KIND_ID_MISMATCH')
    return (system, realm, kind, id_type, identifier)

def build_mapping_matrix(entries):
    if not isinstance(entries,list) or not entries:
        raise MappingMatrixError('EMPTY_MAPPING')
    pairs=[]; seen=set(); forward={}; reverse={}; conflicts=[]
    for index, entry in enumerate(entries):
        if not isinstance(entry,dict) or set(entry) != {'source','target','evidence_ref'}:
            raise MappingMatrixError('INVALID_ENTRY')
        source=_identity(entry['source']); target=_identity(entry['target'])
        if source[2] != target[2]:
            raise MappingMatrixError('KIND_MISMATCH')
        evidence=entry['evidence_ref']
        if not isinstance(evidence,str) or not 1 <= len(evidence) <= 128 or not re.fullmatch(r'[A-Za-z0-9_.:-]+',evidence):
            raise MappingMatrixError('INVALID_EVIDENCE_REF')
        key=(source,target)
        if key in seen:
            raise MappingMatrixError('DUPLICATE_MAPPING')
        seen.add(key)
        if source in forward and forward[source]!=target: conflicts.append({'index':index,'reason':'ONE_TO_MANY_SOURCE'})
        if target in reverse and reverse[target]!=source: conflicts.append({'index':index,'reason':'MANY_TO_ONE_TARGET'})
        forward[source]=target; reverse[target]=source
        pairs.append({'source':dict(zip(('system','realm','kind','id_type','identifier'),source)),
                      'target':dict(zip(('system','realm','kind','id_type','identifier'),target)),
                      'evidence_ref':evidence})
    pairs.sort(key=lambda x: json.dumps(x,sort_keys=True))
    report={'schema':'odmm.identity-mapping-matrix.v1','entries':pairs,'conflicts':conflicts,
            'status':'BLOCKED' if conflicts else 'PENDING_DIRECTORY_VERIFICATION',
            'directory_verified':False,'effective_access_verified':False,'production_qualified':False,
            'limitations':['OFFLINE_OPERATOR_SUPPLIED_IDENTITIES','NO_DIRECTORY_BIND','NO_SID_UID_TRANSLATION_VERIFIED','EVIDENCE_REF_NOT_AUTHENTICATION']}
    canonical=json.dumps(report,sort_keys=True,separators=(',',':'),ensure_ascii=True).encode()
    return {'report':report,'sha256':hashlib.sha256(canonical).hexdigest()}

def verify_mapping_matrix(bundle):
    if not isinstance(bundle,dict) or set(bundle) != {'report','sha256'} or not isinstance(bundle['report'],dict):
        raise MappingMatrixError('INVALID_BUNDLE')
    report=bundle['report']
    if report.get('schema')!='odmm.identity-mapping-matrix.v1' or any(report.get(k) is not False for k in ('directory_verified','effective_access_verified','production_qualified')):
        raise MappingMatrixError('UNSAFE_REPORT')
    rebuilt=build_mapping_matrix(report.get('entries'))
    if rebuilt != bundle: raise MappingMatrixError('REPORT_MISMATCH')
    return True
