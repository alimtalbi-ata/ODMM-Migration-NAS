from odmm_netapp_ontap_v2078 import discover_ontap, qualify_netapp_pair

def fetch(path):
 if '/api/cluster/nodes' in path:return {'records':[{'name':'n1'},{'name':'n2'}]}
 if '/api/cluster?' in path:return {'version':'9.x'}
 if '/api/svm/svms/' in path:return {'name':'svm-data','state':'running'}
 if '/api/storage/volumes/' in path:return {'name':'vol1','nas':{'path':'/vol1'},'svm':{'name':'svm-data'},'snapshot_policy':{'name':'default'},'space':{'size':100}}
 raise AssertionError(path)

def test_discovery_read_only_and_conservative():
 paths=[]
 def wrapped(path):paths.append(path);return fetch(path)
 r=discover_ontap(wrapped,svm_uuid='svm1',volume_uuid='vol1',share_name='data')
 assert len(paths)==4 and all(p.startswith('/api/') for p in paths)
 assert r.endpoint['cluster']['topology']=='scale_out'
 assert r.endpoint['virtualization']['layer']=='svm_vserver'
 assert r.endpoint['identity_domain_verified'] is False

def test_missing_export_blocks():
 r=discover_ontap(fetch,svm_uuid='svm1',volume_uuid='vol1')
 assert 'NETAPP_SHARE_OR_EXPORT_NOT_IDENTIFIED' in r.blockers

def test_outage_fails_closed():
 def broken(path):raise ConnectionError('offline')
 r=discover_ontap(broken,svm_uuid='svm1',volume_uuid='vol1',share_name='x')
 assert r.blockers and 'NETAPP_CLUSTER_DISCOVERY_UNAVAILABLE' in r.blockers

def test_no_cutover_without_proofs():
 r=discover_ontap(fetch,svm_uuid='svm1',volume_uuid='vol1',share_name='data')
 gate=qualify_netapp_pair(r,r)
 assert gate['status']=='BLOCKED' and gate['cutover_authorized'] is False

def test_invalid_id():
 import pytest
 with pytest.raises(ValueError):discover_ontap(fetch,svm_uuid='x/y',volume_uuid='v')
