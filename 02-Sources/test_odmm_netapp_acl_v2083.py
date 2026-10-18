from types import SimpleNamespace
from odmm_netapp_acl_v2083 import collect_acl_evidence,compare_acl_evidence

def inventory():
    return SimpleNamespace(resources={'cifs_shares':[{'uuid':'ignored','svm':{'uuid':'svm-1'},'name':'DATA'}], 'nfs_export_policies':[{'uuid':'policy-1','svm':{'uuid':'svm-1'}}]})

def fetch(path):
    if '/cifs/shares/' in path:return {'acls':[{'user_or_group':'Everyone','permission':'read'}]}
    if '/rules?' in path:return {'records':[{'index':1,'clients':[{'match':'10.0.0.0/8'}],'ro_rule':['sys'],'rw_rule':[]}]}
    raise AssertionError(path)

def test_collect_and_compare():
    a=collect_acl_evidence(fetch,inventory()); assert not a['blockers']; assert not compare_acl_evidence(a,a)['differences']; assert not a['cutover_authorized']

def test_policy_drift():
    a=collect_acl_evidence(fetch,inventory()); b=collect_acl_evidence(fetch,inventory());b['evidence']['cifs_shares'][0]['acls'][0]['permission']='full_control'
    assert 'CIFS_SHARES_POLICY_DRIFT' in compare_acl_evidence(a,b)['blockers']

def test_missing_identifiers_fail_closed():
    i=SimpleNamespace(resources={'cifs_shares':[{'name':'X'}],'nfs_export_policies':[]})
    a=collect_acl_evidence(fetch,i)
    assert 'CIFS_SHARES_IDENTIFIER_MISSING' in a['blockers']

def test_pagination_fail_closed():
    def f(path):
        if '/rules?' in path:return {'records':[],'_links':{'next':{'href':'/api/more'}}}
        return fetch(path)
    assert 'NFS_EXPORT_POLICIES_DETAIL_INCOMPLETE' in collect_acl_evidence(f,inventory())['blockers']

def test_collector_limit():
    assert 'ACL_COLLECTION_LIMIT' in collect_acl_evidence(fetch,inventory(),max_items=1)['blockers']
