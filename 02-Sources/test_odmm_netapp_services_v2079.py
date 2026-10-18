from odmm_netapp_services_v2079 import discover_services, prequalify_services, KINDS

def sample(path):
    if '/interfaces?' in path:return {'records':[{'name':'lif1','state':'up'}]}
    if '/volumes?' in path:return {'records':[{'name':'vol1','style':'mixed','flexgroup':{'name':'fg'}}]}
    if '/shares?' in path:return {'records':[{'name':'share1'}]}
    if '/relationships?' in path:return {'records':[{'state':'snapmirrored'}]}
    return {'records':[]}

def test_all_resources_collected():
    r=discover_services(sample)
    assert set(r.resources)==set(KINDS) and not r.blockers
    assert 'NETAPP_MIXED_SECURITY_STYLE_REQUIRES_EFFECTIVE_ACCESS_TESTS' in r.warnings
    assert r.evidence['lifs']['source']=='ONTAP_REST_READ_ONLY'

def test_fail_closed_on_outage():
    def broken(path):
        if 'shares' in path:raise ConnectionError('offline')
        return sample(path)
    r=discover_services(broken)
    assert 'NETAPP_CIFS_SHARES_DISCOVERY_INCOMPLETE' in r.blockers

def test_pagination():
    def fetch(path):
        if '/interfaces?' in path:return {'records':[{'name':'a'}], '_links':{'next':{'href':'/api/network/ip/interfaces?page=2'}}}
        if 'interfaces?page=2' in path:return {'records':[{'name':'b'}]}
        return sample(path)
    r=discover_services(fetch)
    assert len(r.resources['lifs'])==2 and r.evidence['lifs']['pages']==2

def test_reject_external_pagination():
    def fetch(path):
        if '/interfaces?' in path:return {'records':[{'name':'a'}], '_links':{'next':{'href':'https://evil.example/steal'}}}
        return sample(path)
    r=discover_services(fetch)
    assert 'NETAPP_LIFS_DISCOVERY_INCOMPLETE' in r.blockers

def test_loop_and_limit():
    def fetch(path):
        if '/interfaces?' in path:return {'records':[{'name':'a'}], '_links':{'next':{'href':path}}}
        return sample(path)
    assert 'NETAPP_LIFS_DISCOVERY_INCOMPLETE' in discover_services(fetch).blockers
    def many(path):
        if '/interfaces?' in path:return {'records':[{'name':'a'},{'name':'b'}]}
        return sample(path)
    assert 'NETAPP_LIFS_DISCOVERY_INCOMPLETE' in discover_services(many,max_records=1).blockers

def test_prequalification_never_authorizes():
    r=discover_services(sample)
    gate=prequalify_services(r,r)
    assert gate['status']=='BLOCKED' and gate['cutover_authorized'] is False
    assert 'ACL_EFFECTIVE_ACCESS_TEST_REQUIRED' in gate['blockers']
