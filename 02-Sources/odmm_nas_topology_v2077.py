"""Conservative NAS topology migration qualification. Auteur : Abdelhalim Talbi.
Read-only evidence evaluation: no snapshot creation, ACL change or cutover action.
"""
from dataclasses import dataclass

FEATURES = ('cluster','snapshots','virtualization','identity','protocol','data_consistency','performance')
EVIDENCE = ('OBSERVED','TESTED')

@dataclass(frozen=True)
class NasAssessment:
    status: str
    blockers: tuple
    warnings: tuple
    plan: tuple
    cutover_authorized: bool = False
    schema: str = 'odmm.nas_topology.v2077'


def qualify_nas_migration(source, target, *, workload=None, proofs=None):
    """Fail closed on absent source/target evidence; does not grant cutover.
    Evidence: proofs[feature] = {'source':'OBSERVED','target':'OBSERVED',
    'comparison':'TESTED'}; additional explicit tests as named below.
    """
    workload = workload or {}; proofs = proofs or {}
    blockers=[]; warnings=[]; plan=[]
    if not isinstance(source,dict) or not isinstance(target,dict):
        return NasAssessment('BLOCKED',('INVALID_ENDPOINT',),(),(),False)
    for side,ep in (('source',source),('target',target)):
        if not ep.get('vendor') or not ep.get('model') or not ep.get('firmware'):
            blockers.append(side.upper()+'_INVENTORY_INCOMPLETE')
        if not ep.get('namespace_id') or not ep.get('export_or_share'):
            blockers.append(side.upper()+'_NAMESPACE_UNRESOLVED')
        cluster=ep.get('cluster',{})
        if not isinstance(cluster,dict) or cluster.get('topology') not in ('standalone','active_passive','active_active','scale_out'):
            blockers.append(side.upper()+'_CLUSTER_TOPOLOGY_UNVERIFIED')
        elif cluster['topology'] != 'standalone':
            for f in ('stable_namespace','failover_tested','client_reconnect_tested','node_ownership_verified'):
                if cluster.get(f) is not True: blockers.append(side.upper()+'_CLUSTER_'+f.upper()+'_MISSING')
            plan.append(side+': pin migration to logical namespace, not node IP; qualify failover and reconnect')
        snap=ep.get('snapshots',{})
        if not isinstance(snap,dict) or snap.get('policy') not in ('none','source_consistent','target_protection'):
            blockers.append(side.upper()+'_SNAPSHOT_POLICY_UNKNOWN')
        elif snap['policy']!='none':
            if snap.get('retention_verified') is not True: blockers.append(side.upper()+'_SNAPSHOT_RETENTION_UNVERIFIED')
            if snap.get('space_reserve_verified') is not True: blockers.append(side.upper()+'_SNAPSHOT_COW_CAPACITY_UNVERIFIED')
            if side=='source' and snap.get('consistency') not in ('application_quiesced','filesystem_consistent'):
                blockers.append('SOURCE_SNAPSHOT_CONSISTENCY_UNVERIFIED')
            plan.append(side+': budget snapshot COW, retention, rollback window and application consistency')
        virt=ep.get('virtualization',{})
        if not isinstance(virt,dict) or virt.get('layer') not in ('none','svm_vserver','nas_vm','container_namespace','gateway'):
            blockers.append(side.upper()+'_VIRTUAL_NAMESPACE_UNVERIFIED')
        elif virt['layer']!='none':
            for f in ('tenant_isolation_verified','namespace_mapping_verified','backend_mapping_verified'):
                if virt.get(f) is not True: blockers.append(side.upper()+'_VIRTUAL_'+f.upper()+'_MISSING')
            plan.append(side+': preserve tenant isolation, share/export mapping and backend ownership')
        if ep.get('protocol') not in ('NFSv3','NFSv4','NFSv4.1','SMB2','SMB3','mixed'):
            blockers.append(side.upper()+'_PROTOCOL_UNKNOWN')
        if ep.get('identity_domain_verified') is not True: blockers.append(side.upper()+'_IDENTITY_DOMAIN_UNVERIFIED')
        if ep.get('acl_model') not in ('POSIX','NFSv4','NTFS','MIXED'):
            blockers.append(side.upper()+'_ACL_MODEL_UNKNOWN')
    for feature in FEATURES:
        proof=proofs.get(feature,{})
        if not isinstance(proof,dict) or any(proof.get(k) not in EVIDENCE for k in ('source','target')) or proof.get('comparison')!='TESTED':
            blockers.append('PROOF_'+feature.upper()+'_INCOMPLETE')
    for test in ('content_hash','metadata','acl_raw','effective_access','identity_mapping','open_file_behavior','incremental_delta','rollback_rehearsal'):
        if proofs.get(test)!='PASS': blockers.append('TEST_'+test.upper()+'_MISSING')
    if source.get('acl_model')!=target.get('acl_model'):
        blockers.append('CROSS_ACL_MODEL_TRANSLATION_REQUIRED')
        plan.append('prove canonical ACL translation and effective access for representative principals')
    if source.get('protocol')!=target.get('protocol'):
        blockers.append('CROSS_PROTOCOL_SEMANTICS_REQUIRED')
    if source.get('identity_domain')!=target.get('identity_domain'):
        blockers.append('CROSS_IDENTITY_DOMAIN_MAPPING_REQUIRED')
    if workload.get('change_rate_bytes_s') is None or workload.get('sustainable_copy_bytes_s') is None:
        blockers.append('DELTA_CONVERGENCE_UNMEASURED')
    else:
        change=workload['change_rate_bytes_s']; copy=workload['sustainable_copy_bytes_s']
        if not isinstance(change,(int,float)) or not isinstance(copy,(int,float)) or change<0 or copy<=0:
            blockers.append('INVALID_PERFORMANCE_MEASUREMENTS')
        elif change>=copy: blockers.append('DELTA_WILL_NOT_CONVERGE')
        elif change>copy*.7: warnings.append('DELTA_MARGIN_BELOW_30_PERCENT')
    if workload.get('latency_baseline_ms') is None or workload.get('latency_migration_ms') is None:
        blockers.append('LATENCY_IMPACT_UNMEASURED')
    else:
        a,b=workload['latency_baseline_ms'],workload['latency_migration_ms']
        if not all(isinstance(x,(int,float)) and x>=0 for x in (a,b)):
            blockers.append('INVALID_LATENCY_MEASUREMENTS')
        elif a>0 and b>1.5*a: warnings.append('LATENCY_INCREASE_OVER_50_PERCENT')
    plan.extend(('inventory source and target vendor/model/firmware, cluster and virtual namespace',
        'establish application-consistent baseline and snapshot retention policy',
        'measure throughput, ops/s, latency, change rate and COW amplification under load',
        'test ACL, inheritance, SID/UID/GID, xattr/ADS and effective access across protocols',
        'rehearse failover, open handles, cutover freeze, rollback and post-cutover verification'))
    return NasAssessment('BLOCKED' if blockers else 'READY_FOR_HUMAN_REVIEW',
        tuple(sorted(set(blockers))),tuple(sorted(set(warnings))),tuple(dict.fromkeys(plan)),False)
