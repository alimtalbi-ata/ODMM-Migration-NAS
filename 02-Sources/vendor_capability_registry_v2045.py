"""Evidence-driven vendor protocol capabilities. Auteur : Abdelhalim Talbi.
Documentation is conditional; never infer a live appliance configuration.
"""
from copy import deepcopy

SOURCES = {
 'ibm_storage_scale': {'url':'https://www.ibm.com/docs/en/storage-scale/5.2.3?topic=users-authorizing-file-protocol', 'version':'5.2.3', 'notes':'NFSv4 ACL stored for CES; SMB security descriptor mapping; share ACL separate'},
 'truenas_scale': {'url':'https://www.truenas.com/docs/scale/24.04/scaletutorials/datasets/permissionsscale/', 'version':'24.04', 'notes':'Dataset presets select POSIX versus NFSv4 ACL; SMB and multiprotocol presets differ'},
 'ibm_storage_scale_limits': {'url':'https://www.ibm.com/docs/en/storage-scale/6.0.1?topic=administration-exceptions-limitations-nfsv4-acls-support','version':'6.0.1','notes':'ACL limitations depend on clients and protocol'},
}
# Catalog presence does not mean certified support. Every product requires a specific
# version/configuration and independent read-only source AND target observations.
CATALOG = {
 'ibm_storage_scale': {'family':'IBM Storage Scale','documented_protocols':('NFSv4','SMB3'), 'acl_model':'NFSv4_CES','reference':'ibm_storage_scale'},
 'truenas_scale': {'family':'TrueNAS SCALE','documented_protocols':('NFSv4','SMB3'), 'acl_model':'DATASET_DEPENDENT','reference':'truenas_scale'},
}
DISCOVERY_ONLY = ('pure_flashblade','hpe_alletra_file','hitachi_hnas','synology_dsm','qnap_qts','qnap_hero','minio','ceph_rgw','cloudian_hyperstore','dell_unity','dell_powerscale','netapp_ontap','aws_s3')
FIELDS=('content','owner','group','mode','acl','xattrs','ads','hardlinks','sparse','timestamps','effective_access')

def qualify_pair(source, target, required=('content','acl','effective_access'), proofs=None):
    """Fail closed. Proofs format: {field:{source:'MATCH',target:'MATCH',comparison:'MATCH'}}.
    Does not perform device discovery or issue permission-changing commands.
    """
    proofs=proofs or {}; findings=[]; references={}
    if not required or any(x not in FIELDS for x in required):
        return {'status':'BLOCKED','findings':['INVALID_REQUIREMENTS'],'cutover_authorized':False,'references':{}}
    for side,endpoint in (('source',source),('target',target)):
        if not isinstance(endpoint,dict):
            findings.append(side+':INVALID_ENDPOINT'); continue
        vendor=endpoint.get('vendor'); profile=CATALOG.get(vendor)
        if profile is None:
            findings.append(side+':VENDOR_NOT_DOCUMENTED_FOR_THIS_VERSION')
            continue
        references[side]=deepcopy(SOURCES[profile['reference']])
        if endpoint.get('version') != references[side]['version']:
            findings.append(side+':VERSION_NOT_QUALIFIED')
        if endpoint.get('protocol') not in profile['documented_protocols']:
            findings.append(side+':PROTOCOL_NOT_DOCUMENTED')
        if endpoint.get('identity_mapping_verified') is not True:
            findings.append(side+':IDENTITY_MAPPING_UNVERIFIED')
        if vendor=='ibm_storage_scale':
            if endpoint.get('filesystem_acl_type')!='NFSv4':
                findings.append(side+':CES_NFSV4_ACL_CONFIGURATION_UNVERIFIED')
            if endpoint.get('protocol')=='SMB3' and endpoint.get('share_acl_verified') is not True:
                findings.append(side+':SMB_SHARE_ACL_UNVERIFIED')
        if vendor=='truenas_scale':
            if endpoint.get('dataset_acl_type')!='NFSv4' and 'acl' in required:
                findings.append(side+':DATASET_NFSV4_ACL_UNVERIFIED')
            if endpoint.get('protocol')=='SMB3' and endpoint.get('case_sensitivity_verified') is not True:
                findings.append(side+':CASE_SEMANTICS_UNVERIFIED')
    if isinstance(source,dict) and isinstance(target,dict):
        if source.get('vendor')!=target.get('vendor'): findings.append('CROSS_VENDOR_TRANSLATION_UNVERIFIED')
        if source.get('protocol')!=target.get('protocol'): findings.append('CROSS_PROTOCOL_TRANSLATION_UNVERIFIED')
    for field in required:
        proof=proofs.get(field)
        if not isinstance(proof,dict) or any(proof.get(k)!='MATCH' for k in ('source','target','comparison')):
            findings.append('FIDELITY_'+field.upper()+'_NOT_PROVEN')
    return {'schema':'odmm.vendor_capabilities.v2045','status':'UNVERIFIED' if findings else 'ELIGIBLE_FOR_MANUAL_REVIEW',
            'findings':sorted(set(findings)),'references':references,
            'validation_authorized':False,'cutover_authorized':False}
