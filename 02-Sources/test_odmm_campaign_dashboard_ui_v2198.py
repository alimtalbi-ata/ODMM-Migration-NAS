import pytest
from odmm_campaign_dashboard_ui_v2198 import render_interactive
from odmm_access_audit_v2184 import AuditError
from odmm_campaign_dashboard_v2196 import build_dashboard
from test_odmm_directory_audit_v2195 import run

def test_interactive_filters_and_timeline(tmp_path):
    run(tmp_path)
    r=build_dashboard(tmp_path/'audit.db',tmp_path/'anchor.db')
    page=render_interactive(r)
    assert 'id="identity"' in page and 'id="status"' in page
    assert 'Chronologie des audits' in page and 'addEventListener' in page
    assert 'Cutover interdit' in page

def test_escaping():
    r={'schema':'odmm.campaign-dashboard.v2196','cutover_authorized':False,'anchored':True,'entries':1,'nas_qualified':False,'case_count':1,'mismatch_count':1,'audit_head':'a'*64,'cases':[{'seq':1,'case_id':'<script>alert(1)</script>','identity_ref':'\" onmouseover=\"evil','mismatch':True,'groups_equal':False,'local_access_equal':True}]}
    page=render_interactive(r)
    assert '<script>alert(1)</script>' not in page
    assert '&lt;script&gt;' in page and '&quot; onmouseover=&quot;evil' in page

def test_fail_closed():
    with pytest.raises(AuditError):render_interactive({'schema':'odmm.campaign-dashboard.v2196','cutover_authorized':True})
