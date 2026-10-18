from odmm_netapp_policy_v2084 import collect_nfs_rules,compare_nfs_policies,render_policy_differences

def test_pagination_and_canonical():
    def fetch(p):
        return {'records':[{'index':2,'clients':['b']}], '_links':{'next':{'href':'/api/page2'}}} if p=='/api/start' else {'records':[{'index':1,'clients':['a']}]}
    a=collect_nfs_rules(fetch,'/api/start');assert a['complete'] and a['pages']==2
    b={'rules':list(reversed(a['rules'])),'complete':True,'blockers':[]}
    assert not compare_nfs_policies(a,b)['differences']

def test_external_pagination_blocked():
    a=collect_nfs_rules(lambda _: {'records':[],'_links':{'next':{'href':'https://evil.example/api'}}},'/api/start')
    assert 'UNSAFE_NEXT_LINK' in a['blockers'] and not a['complete']

def test_cycle_blocked():
    a=collect_nfs_rules(lambda _: {'records':[],'_links':{'next':{'href':'/api/start'}}},'/api/start')
    assert 'PAGINATION_CYCLE' in a['blockers']

def test_limits_blocked():
    a=collect_nfs_rules(lambda _: {'records':[{'index':1},{'index':2}]},'/api/start',max_rules=1)
    assert 'RULE_LIMIT_EXCEEDED' in a['blockers']

def test_policy_drift_and_ambiguity():
    a={'complete':True,'rules':[{'index':1,'ro_rule':['sys']}],'blockers':[]}
    b={'complete':True,'rules':[{'index':1,'ro_rule':['none']}],'blockers':[]}
    assert 'NFS_RULE_DRIFT' in compare_nfs_policies(a,b)['blockers']
    b['rules']=[{'index':1},{'index':1}]
    assert 'AMBIGUOUS_POLICY_EVIDENCE' in compare_nfs_policies(a,b)['blockers']

def test_html_escaped():
    s=render_policy_differences({'blockers':['<script>alert(1)</script>'],'differences':[]})
    assert '<script>' not in s and '&lt;script&gt;' in s

def test_never_authorizes():
    a={'complete':True,'rules':[],'blockers':[]}
    assert compare_nfs_policies(a,a)['cutover_authorized'] is False
