"""Conservative documentation index and observed-capability gate.
Auteur : Abdelhalim Talbi. Documentation links are starting points, NOT verified firmware certifications.
"""
from copy import deepcopy

# Official documentation landing pages. Specific feature/version claims require separate evidence.
VENDORS = {
 'netapp_ontap': ('NetApp ONTAP','https://docs.netapp.com/us-en/ontap/'),
 'dell_powerscale': ('Dell PowerScale OneFS','https://www.dell.com/support/home/'),
 'pure_flashblade': ('Pure Storage FlashBlade','https://support.purestorage.com/'),
 'hpe_alletra_file': ('HPE Alletra Storage MP File','https://support.hpe.com/'),
 'hitachi_hnas': ('Hitachi NAS Platform','https://docs.hitachivantara.com/'),
 'synology_dsm': ('Synology DSM','https://kb.synology.com/'),
 'qnap_qts': ('QNAP QTS','https://docs.qnap.com/'),
 'qnap_hero': ('QNAP QuTS hero','https://docs.qnap.com/'),
 'truenas_scale': ('TrueNAS SCALE','https://www.truenas.com/docs/'),
 'ibm_storage_scale': ('IBM Storage Scale','https://www.ibm.com/docs/en/storage-scale'),
 'minio': ('MinIO','https://docs.min.io/'),
 'ceph_rgw': ('Ceph Object Gateway','https://docs.ceph.com/en/latest/radosgw/'),
 'cloudian_hyperstore': ('Cloudian HyperStore','https://cloudian.com/'),
 'aws_s3': ('Amazon S3','https://docs.aws.amazon.com/AmazonS3/latest/userguide/'),
}
REQUIRED_OBSERVATIONS = ('vendor','model','software_version','protocol','protocol_version',
 'acl_model','identity_domain','identity_mapping','case_semantics','unicode_semantics',
 'xattrs','timestamps','symlink_semantics','effective_access')
PROOF_KEYS = ('source','target','comparison')

def evaluate(source, target, required=('content','acl','effective_access'), evidence=None):
    """No device commands, no implied support, no approval; each required field needs triple proof."""
    findings=[]; references={}; evidence=evidence or {}
    if not isinstance(required,(list,tuple)) or not required or not all(isinstance(x,str) and x for x in required):
        return {'status':'BLOCKED','findings':['INVALID_REQUIREMENTS'],'cutover_authorized':False}
    for side,endpoint in (('source',source),('target',target)):
        if not isinstance(endpoint,dict):
            findings.append(side+':INVALID_ENDPOINT');continue
        vendor=endpoint.get('vendor')
        if vendor not in VENDORS:
            findings.append(side+':UNKNOWN_VENDOR');continue
        name,url=VENDORS[vendor]
        references[side]={'product':name,'documentation_index':url,'qualification':'UNVERIFIED'}
        for key in REQUIRED_OBSERVATIONS:
            if not endpoint.get(key): findings.append(side+':MISSING_'+key.upper())
        if endpoint.get('capabilities_observed') is not True:
            findings.append(side+':CAPABILITIES_NOT_OBSERVED')
        if endpoint.get('datasheet_version_verified') is not True:
            findings.append(side+':DOCUMENT_VERSION_NOT_VERIFIED')
    if isinstance(source,dict) and isinstance(target,dict):
        for key in ('protocol','protocol_version','acl_model','identity_domain','case_semantics','unicode_semantics'):
            if source.get(key)!=target.get(key):findings.append('TRANSLATION_'+key.upper()+'_NOT_PROVEN')
    for field in required:
        proof=evidence.get(field)
        if not isinstance(proof,dict) or any(proof.get(k)!='MATCH' for k in PROOF_KEYS):
            findings.append('FIDELITY_'+field.upper()+'_NOT_PROVEN')
    return {'schema':'odmm.vendor_evidence.v2046','status':'UNVERIFIED' if findings else 'ELIGIBLE_FOR_MANUAL_REVIEW',
            'findings':sorted(set(findings)),'references':deepcopy(references),
            'validation_authorized':False,'cutover_authorized':False}
