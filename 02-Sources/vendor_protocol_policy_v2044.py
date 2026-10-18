"""Vendor-aware, fail-closed policy based on cited vendor documentation.
Auteur : Abdelhalim Talbi. Profiles are conditional guidance, NOT device discovery.
"""
from dataclasses import dataclass

DOCS={
 'netapp_ontap': ('https://www.netapp.com/media/27436-tr-4887.pdf','https://docs.netapp.com/us-en/ontap/nfs-admin/security-styles-their-effects-concept.html'),
 'dell_powerscale': ('https://www.dell.com/support/manuals/en-us/isilon-onefs/ifs-pub-91300-administration-guide-gui/identity-types?guid=guid-8c522701-2ee9-4ab1-a0ca-2aefb86d6f3d&lang=en-us',),
 'aws_s3': ('https://docs.aws.amazon.com/AmazonS3/latest/userguide/VersionedObjectPermissionsandACLs.html','https://docs.aws.amazon.com/AmazonS3/latest/user-guide/access-control-overview.html'),
}
KNOWN={'netapp_ontap','dell_powerscale','aws_s3'}
REQUIRED_KEYS=('vendor','protocol','version','security_style','identity_mapping_verified','acl_evidence','metadata_evidence')

def qualify(source,target,*,required=('content','owner','acl','xattrs'), evidence=None):
    """Evaluate declared endpoints; never assume support from product family alone.
    Evidence is supplied by independently run collectors, not auto-generated here.
    """
    evidence=evidence or {}
    problems=[]; unknown=[]
    for side,endpoint in [('source',source),('target',target)]:
        if not isinstance(endpoint,dict):
            problems.append(side+':INVALID_ENDPOINT');continue
        for key in REQUIRED_KEYS:
            if key not in endpoint or endpoint[key] in (None,''):
                unknown.append(side+':MISSING_'+key.upper())
        vendor=endpoint.get('vendor')
        if vendor not in KNOWN: unknown.append(side+':UNQUALIFIED_VENDOR')
        proto=endpoint.get('protocol')
        if proto not in ('NFSv3','NFSv4','NFSv4.1','SMB2','SMB3','S3'):
            unknown.append(side+':UNKNOWN_PROTOCOL')
        if vendor=='aws_s3' and proto!='S3': problems.append(side+':PROTOCOL_CONFLICT')
        if vendor=='netapp_ontap':
            style=endpoint.get('security_style')
            if style not in ('UNIX','NTFS','mixed'): unknown.append(side+':UNKNOWN_SECURITY_STYLE')
            if style=='mixed': unknown.append(side+':MIXED_EFFECTIVE_ACL_REQUIRES_PER_FILE_PROOF')
            if style=='UNIX' and proto in ('SMB2','SMB3') and 'acl' in required:
                unknown.append(side+':SMB_VIEW_NOT_NFSV4_ACL_PROOF')
            if style=='NTFS' and proto and proto.startswith('NFS') and 'acl' in required:
                unknown.append(side+':NFS_VIEW_NOT_NTFS_ACL_PROOF')
        if vendor=='dell_powerscale' and endpoint.get('identity_mapping_verified') is not True:
            unknown.append(side+':IDENTITY_MAPPING_NOT_VERIFIED')
        if vendor=='aws_s3' and 'acl' in required:
            unknown.append(side+':S3_ACCESS_POLICY_NOT_FILE_ACL')
        if 'acl' in required and endpoint.get('acl_evidence') is not True:
            unknown.append(side+':ACL_COLLECTOR_PROOF_MISSING')
        if any(x in required for x in ('owner','xattrs','ads','sparse','hardlinks')) and endpoint.get('metadata_evidence') is not True:
            unknown.append(side+':METADATA_PROOF_MISSING')
    if isinstance(source,dict) and isinstance(target,dict):
        if source.get('protocol')!=target.get('protocol'):
            unknown.append('CROSS_PROTOCOL_SEMANTIC_MAPPING_UNVERIFIED')
        if source.get('vendor')!=target.get('vendor'):
            unknown.append('CROSS_VENDOR_FIDELITY_UNVERIFIED')
        if source.get('security_style')!=target.get('security_style'):
            unknown.append('SECURITY_STYLE_TRANSLATION_UNVERIFIED')
    for field in required:
        if evidence.get(field)!='MATCH': unknown.append('FIELD_'+field.upper()+'_UNVERIFIED')
    if not required: problems.append('EMPTY_REQUIREMENTS')
    return {'schema':'odmm.vendor_protocol_policy.v2044',
            'status':'BLOCKED' if problems else ('UNVERIFIED' if unknown else 'ELIGIBLE_FOR_MANUAL_REVIEW'),
            'problems':sorted(set(problems)),'unverified':sorted(set(unknown)),
            'validation_authorized':False,'cutover_authorized':False,
            'source_documents':{v:DOCS.get(v,()) for v in (source.get('vendor') if isinstance(source,dict) else None,target.get('vendor') if isinstance(target,dict) else None)}}
