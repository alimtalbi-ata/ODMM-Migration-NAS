"""ODMM V200.2 discovery catalog. Listing is NOT certified interoperability.
Author: Abdelhalim Talbi. No network calls, secrets, or engine mutation.
"""
from dataclasses import dataclass
from typing import Tuple

@dataclass(frozen=True)
class StorageSolution:
    vendor: str
    family: str
    protocols: Tuple[str, ...]
    category: str

# Protocols indicate product-family capabilities to investigate, not firmware-level guarantees.
_CATALOG = (
    StorageSolution('NetApp','ONTAP / AFF / FAS',('NFS','SMB','S3'),'enterprise_nas'),
    StorageSolution('NetApp','StorageGRID',('S3',),'object'),
    StorageSolution('Dell','PowerScale / OneFS',('NFS','SMB','S3'),'enterprise_nas'),
    StorageSolution('Dell','Unity XT File',('NFS','SMB'),'enterprise_nas'),
    StorageSolution('Dell','PowerStore File',('NFS','SMB'),'enterprise_nas'),
    StorageSolution('Dell','ECS',('S3',),'object'),
    StorageSolution('Pure Storage','FlashBlade',('NFS','SMB','S3'),'enterprise_nas'),
    StorageSolution('IBM','Storage Scale / Spectrum Scale',('NFS','SMB','S3'),'scale_out'),
    StorageSolution('IBM','Cloud Object Storage',('S3',),'object'),
    StorageSolution('HPE','Alletra File / GreenLake File',('NFS','SMB'),'enterprise_nas'),
    StorageSolution('HPE','StoreEasy',('SMB',),'enterprise_nas'),
    StorageSolution('Hitachi Vantara','VSP One File / HNAS',('NFS','SMB'),'enterprise_nas'),
    StorageSolution('Hitachi Vantara','HCP',('S3',),'object'),
    StorageSolution('Qumulo','Qumulo File Data Platform',('NFS','SMB'),'scale_out'),
    StorageSolution('VAST Data','VAST Data Platform',('NFS','SMB','S3'),'scale_out'),
    StorageSolution('WEKA','WEKA Data Platform',('NFS','SMB','S3'),'scale_out'),
    StorageSolution('DDN','EXAScaler / Lustre',('NFS',),'parallel_fs'),
    StorageSolution('Cloudian','HyperStore',('S3',),'object'),
    StorageSolution('Scality','RING',('S3',),'object'),
    StorageSolution('Scality','ARTESCA',('S3',),'object'),
    StorageSolution('MinIO','AIStor / MinIO',('S3',),'object'),
    StorageSolution('Ceph','CephFS / RGW',('NFS','SMB','S3'),'software_defined'),
    StorageSolution('iXsystems','TrueNAS SCALE / Enterprise',('NFS','SMB','S3'),'nas'),
    StorageSolution('Synology','DiskStation / RackStation',('NFS','SMB','S3'),'nas'),
    StorageSolution('QNAP','QTS / QuTS hero',('NFS','SMB','S3'),'nas'),
    StorageSolution('OpenZFS','ZFS on Linux / FreeBSD',('NFS','SMB'),'software_defined'),
    StorageSolution('Microsoft','Windows Server File Services',('SMB','NFS'),'software_defined'),
    StorageSolution('Samba','Samba File Server',('SMB',),'software_defined'),
    StorageSolution('Nutanix','Files / Objects',('NFS','SMB','S3'),'scale_out'),
    StorageSolution('Red Hat','OpenShift Data Foundation / Ceph',('NFS','S3'),'software_defined'),
    StorageSolution('Hammerspace','Global Data Platform',('NFS','SMB'),'scale_out'),
    StorageSolution('Nasuni','Nasuni File Data Platform',('SMB','NFS'),'cloud_nas'),
    StorageSolution('Panzura','CloudFS',('SMB','NFS'),'cloud_nas'),
    StorageSolution('AWS','S3 / FSx / EFS',('S3','NFS','SMB'),'cloud'),
    StorageSolution('Microsoft Azure','Blob / Azure Files / Azure NetApp Files',('S3','NFS','SMB'),'cloud'),
    StorageSolution('Google Cloud','Cloud Storage / Filestore',('S3','NFS'),'cloud'),
    StorageSolution('Wasabi','Hot Cloud Storage',('S3',),'cloud_object'),
    StorageSolution('Backblaze','B2 Cloud Storage',('S3',),'cloud_object'),
    StorageSolution('OVHcloud','Object Storage / NAS-HA',('S3','NFS','SMB'),'cloud'),
    StorageSolution('Cloudflare','R2',('S3',),'cloud_object'),
    StorageSolution('DigitalOcean','Spaces',('S3',),'cloud_object'),
)
PROTOCOLS = frozenset(('NFS','SMB','S3'))
REQUIRED_FIDELITY = ('content','mtime','mode','owner','group','acl','xattr','hardlinks','symlinks','sparse','ads','smb_security_descriptor','object_metadata','object_tags','object_versioning')

def solutions(*, protocol=None, vendor=None, category=None):
    if protocol is not None and protocol not in PROTOCOLS: raise ValueError('UNKNOWN_PROTOCOL')
    if vendor is not None and not isinstance(vendor,str): raise ValueError('INVALID_VENDOR')
    if category is not None and not isinstance(category,str): raise ValueError('INVALID_CATEGORY')
    return [s for s in _CATALOG if (protocol is None or protocol in s.protocols) and (vendor is None or vendor.casefold() in s.vendor.casefold()) and (category is None or s.category == category)]

def assess_pair(source, target, *, evidence=None):
    """Never infer ACL fidelity from protocol labels. Requires explicit verified evidence."""
    if source not in _CATALOG or target not in _CATALOG: raise ValueError('UNKNOWN_SOLUTION')
    common = sorted(set(source.protocols) & set(target.protocols))
    result = {'source':f'{source.vendor} / {source.family}', 'target':f'{target.vendor} / {target.family}',
              'candidate_protocols':common, 'status':'DISCOVERY_ONLY', 'cutover_authorized':False,
              'native_engine_default':True, 'external_fallback_requires_approval':True,
              'acl_fidelity_verified':False, 'missing_evidence':list(REQUIRED_FIDELITY),
              'warnings':['CATALOG_NOT_VENDOR_CERTIFICATION','CROSS_PROTOCOL_SEMANTICS_NOT_EQUIVALENT']}
    if evidence is not None:
        if not isinstance(evidence,dict): raise ValueError('INVALID_EVIDENCE')
        result['missing_evidence'] = [k for k in REQUIRED_FIDELITY if evidence.get(k) is not True]
        result['evidence_reported_complete'] = not result['missing_evidence']
        # Self-reported booleans are not sufficient for verified effective access or cutover.
    return result

def export_catalog():
    return {'schema':'odmm.storage.catalog.v2002','author':'Abdelhalim Talbi',
            'qualification':'DISCOVERY_ONLY','production_qualified':False,
            'solutions':[{'vendor':s.vendor,'family':s.family,'protocols':list(s.protocols),'category':s.category} for s in _CATALOG],
            'fidelity_dimensions':list(REQUIRED_FIDELITY)}
