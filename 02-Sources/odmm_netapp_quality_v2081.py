"""NetApp quality/identity and replication risk preflight, no cutover authority.
Auteur: Abdelhalim Talbi.
"""
from odmm_netapp_mapping_v2080 import compare_mappings

def assess_pair(source,target, *, access_evidence=None, acl_evidence=None):
    report=compare_mappings(source,target)
    issues=set(report['blockers']); warnings=set(report['warnings'])
    for side, inv in (('SOURCE',source),('TARGET',target)):
        r=inv.resources
        for volume in r.get('volumes',()):
            if volume.get('flexgroup'):
                issues.add(side+'_FLEXGROUP_CONSTITUENTS_AND_LAYOUT_UNVERIFIED')
            nas=volume.get('nas') or {}
            if str(nas.get('security_style') or volume.get('style') or '').lower()=='mixed':
                issues.add(side+'_MIXED_STYLE_SID_UID_GID_ACCESS_UNVERIFIED')
            if not volume.get('snapshot_policy'):
                warnings.add(side+'_SNAPSHOT_RETENTION_UNVERIFIED')
        for relation in r.get('snapmirror',()):
            if relation.get('healthy') is not True or str(relation.get('state','')).lower() not in ('snapmirrored','in_sync'):
                issues.add(side+'_SNAPMIRROR_STATE_OR_LAG_UNVERIFIED')
            else:
                warnings.add(side+'_SNAPMIRROR_CUTOVER_ORDER_REQUIRED')
        for share in r.get('cifs_shares',()):
            if not share.get('acls'):
                issues.add(side+'_SMB_SHARE_ACL_INVENTORY_MISSING')
        if r.get('nfs_export_policies'):
            issues.add(side+'_NFS_EXPORT_RULES_AND_EFFECTIVE_ACCESS_UNVERIFIED')
    report.update(schema='odmm.netapp.quality.v2081',blockers=sorted(issues),warnings=sorted(warnings),
                  cutover_authorized=False,status='BLOCKED',
                  quality_checks={'smb_share_acl':'REQUIRES_PROOF','ntfs_nfs4_acl':'REQUIRES_PROOF',
                                  'identity_sid_uid_gid':'REQUIRES_PROOF','snapshot_consistency':'REQUIRES_PROOF',
                                  'snapmirror_rpo':'REQUIRES_PROOF','ha_failover':'REQUIRES_PROOF'})
    if access_evidence is not None:
        from odmm_netapp_access_v2082 import assess_access_evidence
        evidence=assess_access_evidence(**access_evidence)
        report['access_evidence']=evidence
        report['blockers']=sorted(set(report['blockers']+evidence['blockers']))
    if acl_evidence is not None:
        from odmm_netapp_acl_v2083 import compare_acl_evidence
        acl_report=compare_acl_evidence(**acl_evidence)
        report['acl_evidence']=acl_report
        report['blockers']=sorted(set(report['blockers']+acl_report['blockers']))
    return report
