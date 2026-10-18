from odmm_runtime_qualification_v2250 import qualify

def test_runtime_v2250():
    result=qualify()
    assert result['status']=='PASS_WITH_UNQUALIFIED_ITEMS',result
    assert all(c['status']!='FAIL' for c in result['checks']),result

def test_authentication_guards_v2250():
    result=qualify()
    assert next(c for c in result['checks'] if c['name']=='full-auth-required')['status']=='PASS'
    assert next(c for c in result['checks'] if c['name']=='scoped-auth-required')['status']=='PASS'
