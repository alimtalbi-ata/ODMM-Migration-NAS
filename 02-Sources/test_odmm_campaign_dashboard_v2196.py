import pytest
from odmm_campaign_dashboard_v2196 import build_dashboard,render_html
from odmm_access_audit_v2184 import AuditError
from test_odmm_directory_audit_v2195 import run,inputs
from odmm_ldap_membership_v2192 import _hash

def test_dashboard_and_html(tmp_path):
    run(tmp_path)
    r=build_dashboard(tmp_path/'audit.db',tmp_path/'anchor.db')
    assert r['case_count']==1 and r['mismatch_count']==0 and r['cutover_authorized'] is False
    assert '<table>' in render_html(r)

def test_filter_and_mismatch(tmp_path):
    d,c=inputs();d['report']['resolved_members']['cn=g,dc=x']=[];d['sha256']=_hash(d['report'])
    run(tmp_path,d,c)
    a=tmp_path/'audit.db';b=tmp_path/'anchor.db'
    assert build_dashboard(a,b,identity='a',only_mismatches=True)['mismatch_count']==1
    assert build_dashboard(a,b,identity='missing')['case_count']==0

def test_anchor_mismatch_blocks(tmp_path):
    run(tmp_path)
    (tmp_path/'anchor.db').unlink()
    with pytest.raises(AuditError):build_dashboard(tmp_path/'audit.db',tmp_path/'anchor.db')

def test_html_escape():
    r={'schema':'odmm.campaign-dashboard.v2196','cutover_authorized':False,'case_count':1,'mismatch_count':0,'audit_head':'a', 'cases':[{'seq':1,'case_id':'<script>alert(1)</script>','identity_ref':'a','mismatch':False,'groups_equal':True,'local_access_equal':True}]}
    s=render_html(r)
    assert '<script>' not in s and '&lt;script&gt;' in s
