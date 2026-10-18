import copy
from odmm_nas_topology_v2077 import qualify_nas_migration

def endpoint():
 return dict(vendor='TestVendor',model='lab',firmware='1',namespace_id='ns',export_or_share='/data',
 cluster=dict(topology='standalone'),snapshots=dict(policy='none'),virtualization=dict(layer='none'),
 protocol='SMB3',identity_domain_verified=True,identity_domain='LAB',acl_model='NTFS')
def proofs():
 p={f:dict(source='OBSERVED',target='OBSERVED',comparison='TESTED') for f in
 ('cluster','snapshots','virtualization','identity','protocol','data_consistency','performance')}
 p.update({f:'PASS' for f in ('content_hash','metadata','acl_raw','effective_access','identity_mapping','open_file_behavior','incremental_delta','rollback_rehearsal')})
 return p
def workload(): return dict(change_rate_bytes_s=10,sustainable_copy_bytes_s=100,latency_baseline_ms=2,latency_migration_ms=2.2)
def test_review_not_automatic_cutover():
 r=qualify_nas_migration(endpoint(),endpoint(),workload=workload(),proofs=proofs())
 assert r.status=='READY_FOR_HUMAN_REVIEW' and not r.cutover_authorized

def test_missing_evidence_blocks():
 assert qualify_nas_migration(endpoint(),endpoint()).status=='BLOCKED'
def test_cluster_requires_failover():
 e=endpoint();e['cluster']={'topology':'scale_out'}
 r=qualify_nas_migration(e,endpoint(),workload=workload(),proofs=proofs())
 assert 'SOURCE_CLUSTER_FAILOVER_TESTED_MISSING' in r.blockers

def test_snapshot_consistency_and_cow():
 e=endpoint();e['snapshots']={'policy':'source_consistent'}
 r=qualify_nas_migration(e,endpoint(),workload=workload(),proofs=proofs())
 assert 'SOURCE_SNAPSHOT_CONSISTENCY_UNVERIFIED' in r.blockers
 assert 'SOURCE_SNAPSHOT_COW_CAPACITY_UNVERIFIED' in r.blockers

def test_virtual_tenant_isolation():
 e=endpoint();e['virtualization']={'layer':'svm_vserver'}
 r=qualify_nas_migration(e,endpoint(),workload=workload(),proofs=proofs())
 assert 'SOURCE_VIRTUAL_TENANT_ISOLATION_VERIFIED_MISSING' in r.blockers

def test_acl_translation_blocks():
 t=endpoint();t['acl_model']='NFSv4'
 assert 'CROSS_ACL_MODEL_TRANSLATION_REQUIRED' in qualify_nas_migration(endpoint(),t,workload=workload(),proofs=proofs()).blockers

def test_delta_nonconvergence():
 w=workload();w['change_rate_bytes_s']=120
 assert 'DELTA_WILL_NOT_CONVERGE' in qualify_nas_migration(endpoint(),endpoint(),workload=w,proofs=proofs()).blockers

def test_high_latency_warning():
 w=workload();w['latency_migration_ms']=4
 assert 'LATENCY_INCREASE_OVER_50_PERCENT' in qualify_nas_migration(endpoint(),endpoint(),workload=w,proofs=proofs()).warnings

def test_missing_inventory():
 e=endpoint();del e['firmware']
 assert 'SOURCE_INVENTORY_INCOMPLETE' in qualify_nas_migration(e,endpoint(),workload=workload(),proofs=proofs()).blockers
