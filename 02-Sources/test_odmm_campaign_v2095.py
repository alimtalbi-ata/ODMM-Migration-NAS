import copy
import pytest
from odmm_campaign_v2095 import assess_campaign,verify_campaign
from odmm_qualification_v2094 import consolidate

def report(campaign='camp1', observed='2026-10-15T12:00:00Z'):
    lif=lambda node:[{'lif_id':'lif1','svm':'svm1','protocol':'SMB','home_node':'n1','current_node':node,'operational':True,'session_revalidated':False}]
    return consolidate(campaign_id=campaign,source_lifs=lif('n1'),target_lifs=lif('n2'),migration_preflight={'cutover_authorized':False,'reason':'REKEY_REQUIRED'},audit_rows=[],checkpoint=None,checkpoint_resolver=None,observed_at=observed)

def test_valid_report_still_blocked():
    result=assess_campaign('camp1',[report()]);assert result['report_count']==1 and result['status']=='BLOCKED' and result['cutover_authorized'] is False
    assert verify_campaign(result)
def test_tamper_rejected():
    r=report();r['status']='READY';result=assess_campaign('camp1',[r]);assert result['report_count']==0 and 'INVALID_OR_FOREIGN_REPORT' in result['blockers']
def test_foreign_campaign_rejected():
    assert assess_campaign('camp1',[report('camp2')])['report_count']==0
def test_duplicate_detected():
    result=assess_campaign('camp1',[report(),report()]);assert result['report_count']==1 and 'DUPLICATE_REPORT' in result['blockers']
def test_multiple_reports():
    result=assess_campaign('camp1',[report(),report(observed='2026-10-15T13:00:00Z')]);assert result['report_count']==2
def test_digest_tamper():
    result=assess_campaign('camp1',[report()]);result['report_count']=200;assert not verify_campaign(result)
@pytest.mark.parametrize('id',['','a/b','x'*129,'é'])
def test_bad_campaign_id(id):
    with pytest.raises(ValueError):assess_campaign(id,[report()])
@pytest.mark.parametrize('reports',[[],{},[None]*501])
def test_bad_reports(reports):
    with pytest.raises(ValueError):assess_campaign('camp1',reports)
def test_report_falsely_authorized():
    r=report();r['cutover_authorized']=True;assert assess_campaign('camp1',[r])['report_count']==0
