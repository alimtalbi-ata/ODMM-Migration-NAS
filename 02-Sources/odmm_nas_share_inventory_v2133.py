"""Read-only normalized NFS/SMB namespace evidence; author Abdelhalim Talbi.

Input comes from a caller-provided, separately qualified vendor collector.
No vendor-specific REST routes are assumed and no write is performed.
"""
from dataclasses import dataclass
from collections.abc import Mapping
import hashlib
import json
import re

VENDORS=frozenset(('netapp_ontap','pure_flashblade','dell_onefs'))
KINDS=frozenset(('NFS','SMB'))

@dataclass(frozen=True)
class NamespaceEvidence:
    vendor: str
    firmware: str
    endpoint_id: str
    exports: tuple
    shares: tuple
    digest: str
    blockers: tuple
    cutover_authorized: bool = False
    certified: bool = False
    engine: str = 'ODMM_NATIVE'

def _nonempty(v, maxlen=512):
    return isinstance(v,str) and 0<len(v)<=maxlen and not any(ord(c)<32 or ord(c)==127 for c in v)

def normalize_namespaces(*, vendor, firmware, endpoint_id, records, pagination_complete=False, provenance=None):
    if vendor not in VENDORS or not _nonempty(firmware,128) or not _nonempty(endpoint_id,128):
        raise ValueError('ENDPOINT_IDENTITY_INVALID')
    if type(records) not in (list,tuple) or len(records)>100000:
        raise ValueError('RECORDS_INVALID')
    if pagination_complete is not True:
        raise ValueError('PAGINATION_INCOMPLETE')
    if not isinstance(provenance,Mapping) or not _nonempty(provenance.get('evidence_id'),128) or not _nonempty(provenance.get('collector_id'),128):
        raise ValueError('PROVENANCE_MISSING')
    if provenance.get('vendor')!=vendor or provenance.get('endpoint_id')!=endpoint_id or provenance.get('firmware')!=firmware:
        raise ValueError('PROVENANCE_MISMATCH')
    out={'NFS':[], 'SMB':[]}; seen=set()
    for item in records:
        if not isinstance(item,Mapping) or item.get('vendor')!=vendor or item.get('endpoint_id')!=endpoint_id:
            raise ValueError('RECORD_ENDPOINT_MISMATCH')
        kind=item.get('kind'); name=item.get('name'); path=item.get('path')
        if kind not in KINDS or not _nonempty(name,256) or not _nonempty(path,2048) or not path.startswith('/') or '\\' in path or any(x in ('.','..') for x in path.split('/')):
            raise ValueError('NAMESPACE_RECORD_INVALID')
        if kind=='NFS' and name!=path:
            raise ValueError('NFS_EXPORT_PATH_MISMATCH')
        if kind=='SMB' and ('/' in name or '\\' in name):
            raise ValueError('SMB_SHARE_NAME_INVALID')
        key=(kind,name.casefold() if kind=='SMB' else name)
        if key in seen:
            raise ValueError('DUPLICATE_NAMESPACE')
        seen.add(key)
        if item.get('acl_verified') is True or item.get('identity_verified') is True:
            # A collector assertion alone cannot independently prove access fidelity.
            raise ValueError('UNTRUSTED_FIDELITY_ASSERTION')
        out[kind].append((name,path))
    exports=tuple(sorted(out['NFS'])); shares=tuple(sorted(out['SMB']))
    payload={'schema':'odmm.nas.namespaces.v2133','vendor':vendor,'firmware':firmware,'endpoint_id':endpoint_id,
             'exports':exports,'shares':shares,'provenance':{k:provenance[k] for k in ('evidence_id','collector_id','vendor','endpoint_id','firmware')}}
    digest=hashlib.sha256(json.dumps(payload,sort_keys=True,separators=(',',':')).encode()).hexdigest()
    return NamespaceEvidence(vendor,firmware,endpoint_id,exports,shares,digest,
        ('ACL_FIDELITY_UNVERIFIED','IDENTITY_MAPPING_UNVERIFIED','EFFECTIVE_ACCESS_NOT_PROBED',
         'VENDOR_API_NOT_INDEPENDENTLY_QUALIFIED','DISTRIBUTED_FENCING_NOT_VERIFIED'))

def compare_namespaces(source,target):
    if not isinstance(source,NamespaceEvidence) or not isinstance(target,NamespaceEvidence) or source.vendor==target.vendor:
        raise ValueError('PAIR_INVALID')
    missing_nfs=tuple(sorted(set(source.exports)-set(target.exports)))
    missing_smb=tuple(sorted(set(source.shares)-set(target.shares)))
    return {'source_vendor':source.vendor,'target_vendor':target.vendor,'source_digest':source.digest,
            'target_digest':target.digest,'missing_nfs':missing_nfs,'missing_smb':missing_smb,
            'blockers':tuple(sorted(set(source.blockers+target.blockers+('CUTOVER_NOT_AUTHORIZED',)))),
            'status':'BLOCKED','engine':'ODMM_NATIVE','cutover_authorized':False}
