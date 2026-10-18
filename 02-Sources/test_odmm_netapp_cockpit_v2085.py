from fastapi import FastAPI
from fastapi.testclient import TestClient
from odmm_netapp_cockpit_v2085 import assess_differences,render_differences,attach_netapp_differences

def evidence():
    def row(principal,allowed):
        return {'principal':principal,'protocol':'SMB','path':'/data','operation':'read','expected':allowed,'observed':allowed,'identity_source':'SID'}
    return dict(source_policy={'complete':True,'rules':[{'index':1,'rw_rule':['sys']}]},target_policy={'complete':True,'rules':[{'index':1,'rw_rule':['none']}]},source_tests=[row('S-1',True)],target_tests=[row('T-1',False)],identity_mappings=[{'kind':'SID','source':'S-1','target':'T-1'}])

def client(authorize=lambda req:True,provider=evidence):
    app=FastAPI();attach_netapp_differences(app,authorize=authorize,get_evidence=provider);return TestClient(app)

def test_policy_and_effective_access_drift():
    r=assess_differences(**evidence());assert {'NFS_RULE_DRIFT','EFFECTIVE_ACCESS_DRIFT'}<=set(r['blockers']);assert r['cutover_authorized'] is False

def test_routes_require_auth():
    c=client(authorize=lambda req:False)
    assert c.get('/operations/netapp/differences').status_code==403
    assert c.get('/api/v1/operations/netapp/differences').status_code==403

def test_routes_success():
    c=client();assert c.get('/api/v1/operations/netapp/differences').json()['status']=='BLOCKED'
    r=c.get('/operations/netapp/differences');assert r.status_code==200 and 'BASCULE INTERDITE' in r.text and r.headers['cache-control']=='no-store'

def test_fail_closed_on_provider_failure():
    def fail():raise RuntimeError('private secret')
    r=client(provider=fail).get('/api/v1/operations/netapp/differences');assert r.status_code==503 and 'private secret' not in r.text

def test_html_escapes_untrusted_values():
    s=render_differences({'blockers':['<script>alert(1)</script>'],'access_differences':[{'path':'<img src=x onerror=alert(1)>'}]})
    assert '<script>' not in s and '<img' not in s and '&lt;script&gt;' in s

def test_authorizer_exception_denied():
    def bad(req):raise RuntimeError('error')
    assert client(authorize=bad).get('/operations/netapp/differences').status_code==403
