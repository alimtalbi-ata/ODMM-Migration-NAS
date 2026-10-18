import re
from odmm_campaign_dashboard_ui_v2198 import render_hardened
from test_odmm_campaign_dashboard_ui_v2198 import test_escaping

def report():
    return {'schema':'odmm.campaign-dashboard.v2196','cutover_authorized':False,'anchored':True,'entries':2,'nas_qualified':False,'case_count':2,'mismatch_count':1,'audit_head':'a'*64,'cases':[{'seq':1,'case_id':'a','identity_ref':'user1','mismatch':True,'groups_equal':True,'local_access_equal':False},{'seq':2,'case_id':'b','identity_ref':'user2','mismatch':False,'groups_equal':True,'local_access_equal':True}]}

def test_severity_filter():
    page=render_hardened(report())
    assert 'id="severity"' in page and 'data-severity="critical"' in page and 'data-severity="ok"' in page
    assert "severity.addEventListener('change',filter)" in page

def test_csp_hash_and_no_external_scripts():
    page=render_hardened(report())
    assert 'Content-Security-Policy' in page and "script-src &#x27;sha256-" in page
    assert "connect-src &#x27;none&#x27;" in page and '<script src=' not in page

def test_escape_regression():
    test_escaping()
