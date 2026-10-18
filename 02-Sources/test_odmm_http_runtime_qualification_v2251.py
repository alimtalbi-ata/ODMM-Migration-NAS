from odmm_http_runtime_qualification_v2251 import qualify

def test_http_startup_and_access_controls():
    result=qualify()
    assert result['status']=='PASS_WITH_UNQUALIFIED_ITEMS',result
    assert len([x for x in result['checks'] if x['status']=='PASS'])>=6

def test_unqualified_items_explicit():
    result=qualify()
    assert {'windows-native-execution','nas-nfs-smb-e2e','real-oidc-idp'} <= {x['name'] for x in result['checks'] if x['status']=='NOT_TESTED'}
