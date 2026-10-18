"""Dashboard integrity regression. Author: Abdelhalim Talbi."""
import copy
import pytest
from odmm_access_audit_v2184 import AuditError
from odmm_campaign_dashboard_ui_v2198 import render_hardened
from test_odmm_campaign_dashboard_ui_v2199 import report

def test_valid():
    assert 'ODMM' in render_hardened(report())

@pytest.mark.parametrize('mutate',[
    lambda r:r.update(case_count=99),
    lambda r:r.update(mismatch_count=99),
    lambda r:r['cases'][0].update(mismatch=not r['cases'][0]['mismatch']),
    lambda r:r['cases'][0].update(seq=99999),
    lambda r:r['cases'][0].update(identity_ref=''),
    lambda r:r.update(audit_head='bad'),
    lambda r:r.update(nas_qualified=True),
    lambda r:r.update(anchored=False),
    lambda r:r.update(entries=-1),
])
def test_reject_inconsistent(mutate):
    r=copy.deepcopy(report());mutate(r)
    with pytest.raises(AuditError):render_hardened(r)
