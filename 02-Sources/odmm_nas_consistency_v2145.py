"""Read-only cross-check of NAS namespace, identity and access evidence.
Author: Abdelhalim Talbi. Not a hardware certification or cutover gate.
"""
from hashlib import sha256
import json
from collections.abc import Mapping

VENDORS=frozenset(('netapp_ontap','pure_flashblade','dell_onefs'))

def _records(value, label, maximum=10000):
    if type(value) is not list or len(value)>maximum:
        raise ValueError('INVALID_'+label)
    if any(type(row) is not dict for row in value):
        raise ValueError('INVALID_'+label)
    return value

def crosscheck(*, vendor, namespaces, identities, accesses):
    """Validate operator-normalized snapshots, not vendor-native schemas.

    namespaces: [{path, protocol}]; identities: [{principal, resolved}];
    accesses: [{path, protocol, principal, right, allowed}].
    Every access must reference an existing namespace and resolved identity.
    """
    if vendor not in VENDORS: raise ValueError('INVALID_VENDOR')
    ns=_records(namespaces,'NAMESPACES'); ids=_records(identities,'IDENTITIES'); ac=_records(accesses,'ACCESSES')
    paths=set(); principals=set(); seen=set(); issues=[]
    for row in ns:
        if set(row)!= {'path','protocol'} or type(row['path']) is not str or not row['path'].startswith('/') or row['protocol'] not in ('NFS3','NFS4','SMB2','SMB3'):
            raise ValueError('INVALID_NAMESPACE_ROW')
        key=(row['path'],row['protocol'])
        if key in paths: raise ValueError('DUPLICATE_NAMESPACE')
        paths.add(key)
    for row in ids:
        if set(row)!= {'principal','resolved'} or type(row['principal']) is not str or not row['principal'].strip() or type(row['resolved']) is not bool:
            raise ValueError('INVALID_IDENTITY_ROW')
        if row['principal'] in principals: raise ValueError('DUPLICATE_IDENTITY')
        principals.add(row['principal'])
    resolved={row['principal'] for row in ids if row['resolved'] is True}
    for row in ac:
        if set(row)!= {'path','protocol','principal','right','allowed'} or any(type(row[k]) is not str for k in ('path','protocol','principal','right')) or type(row['allowed']) is not bool or row['right'] not in ('READ','WRITE','EXECUTE','DELETE','READ_ACL','WRITE_ACL','CHANGE_OWNER'):
            raise ValueError('INVALID_ACCESS_ROW')
        key=(row['path'],row['protocol'],row['principal'],row['right'])
        if key in seen: raise ValueError('DUPLICATE_ACCESS')
        seen.add(key)
        if (row['path'],row['protocol']) not in paths: issues.append('ACCESS_NAMESPACE_NOT_IN_INVENTORY')
        if row['principal'] not in resolved: issues.append('ACCESS_IDENTITY_UNRESOLVED')
    digest=sha256(json.dumps({'vendor':vendor,'namespaces':ns,'identities':ids,'accesses':ac},sort_keys=True,ensure_ascii=False,separators=(',',':')).encode()).hexdigest()
    return {'vendor':vendor,'namespace_count':len(ns),'identity_count':len(ids),'access_count':len(ac),'issues':sorted(set(issues)),'digest':digest,'status':'BLOCKED','cutover_authorized':False,'independently_attested':False,'engine':'ODMM_NATIVE'}
