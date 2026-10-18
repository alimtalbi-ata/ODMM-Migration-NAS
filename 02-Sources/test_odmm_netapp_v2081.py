from fastapi import FastAPI
from fastapi.testclient import TestClient
from odmm_netapp_services_v2079 import ServiceInventory
from odmm_netapp_quality_v2081 import assess_pair
from odmm_netapp_portal_v2081 import attach_netapp_preflight

def inventory(*,mixed=False,flex=False,mirror=False,share_acl=True):
    resources={'volumes':({'name':'data','svm':{'uuid':'svm1'},'nas':{'path':'/data','security_style':'mixed' if mixed else 'ntfs','export_policy':'default'},'flexgroup':flex},),
      'cifs_shares':({'name':'team','svm':{'uuid':'svm1'},'path':'/data/team','acls':[{'user':'DOMAIN\\users'}] if share_acl else []},),
      'nfs_export_policies':({'name':'default','svm':{'uuid':'svm1'}},),
      'lifs':({'name':'lif1','svm':{'uuid':'svm1'}},),
      'snapmirror':({'healthy':False,'state':'broken_off'},) if mirror else ()}
    return ServiceInventory(resources,(),(),{})

def test_quality_fail_closed():
    r=assess_pair(inventory(),inventory());assert r['status']=='BLOCKED' and r['cutover_authorized'] is False

def test_flexgroup_and_mixed():
    r=assess_pair(inventory(flex=True,mixed=True),inventory());assert 'SOURCE_FLEXGROUP_CONSTITUENTS_AND_LAYOUT_UNVERIFIED' in r['blockers'];assert 'SOURCE_MIXED_STYLE_SID_UID_GID_ACCESS_UNVERIFIED' in r['blockers']

def test_snapmirror_and_share_acl():
    r=assess_pair(inventory(mirror=True,share_acl=False),inventory());assert 'SOURCE_SNAPMIRROR_STATE_OR_LAG_UNVERIFIED' in r['blockers'];assert 'SOURCE_SMB_SHARE_ACL_INVENTORY_MISSING' in r['blockers']

def make_app(authorize=lambda request:True, get_inventories=lambda:(inventory(),inventory())):
    app=FastAPI();attach_netapp_preflight(app,authorize=authorize,get_inventories=get_inventories);return TestClient(app)

def test_auth_denied_both_routes():
    c=make_app(authorize=lambda request:False)
    assert c.get('/operations/netapp').status_code==403
    assert c.get('/api/v1/operations/netapp/preflight').status_code==403

def test_api_and_dashboard():
    c=make_app();r=c.get('/api/v1/operations/netapp/preflight');assert r.status_code==200 and r.json()['cutover_authorized'] is False
    h=c.get('/operations/netapp');assert h.status_code==200 and 'CUTOVER INTERDIT' in h.text
    assert 'no-store'==h.headers['cache-control']

def test_inventory_failure():
    def fail():raise RuntimeError('secret credentials')
    c=make_app(get_inventories=fail);r=c.get('/api/v1/operations/netapp/preflight');assert r.status_code==503 and 'secret' not in r.text

def test_injected_html_escaped():
    x=inventory();x.resources['volumes'][0]['name']='<script>alert(1)</script>'
    c=make_app(get_inventories=lambda:(x,inventory()))
    assert '<script>alert(1)</script>' not in c.get('/operations/netapp').text
