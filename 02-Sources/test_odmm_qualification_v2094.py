import copy
import pytest
from odmm_qualification_v2094 import consolidate,verify_report_digest

def lif(node,validated):
    return [{'lif_id':'lif1','svm':'svm1','protocol':'SMB','home_node':'n1','current_node':node,'operational':True,'session_revalidated':validated}]

def report(**kwargs):
    args=dict(campaign_id='c1',source_lifs=lif('n1',True),target_lifs=lif('n2',False),migration_preflight={'status':'BLOCKED','reason':'REKEY_REQUIRED','cutover_authorized':False},audit_rows=[],checkpoint=None,checkpoint_resolver=None,observed_at='2026-10-15T00:00:00Z')
    args.update(kwargs)
    return consolidate(**args)

def test_fail_closed():
    r=report();assert r['status']=='BLOCKED' and not r['cutover_authorized']
    assert 'SESSION_CONTINUITY_NOT_PROVEN' in r['blockers']
    assert 'AUDIT_CHAIN_INVALID' in r['blockers']
    assert 'AUDIT_CHECKPOINT_INVALID' in r['blockers']

def test_digest():
    r=report();assert verify_report_digest(r)
    r['campaign_id']='tampered';assert not verify_report_digest(r)

def test_deterministic():
    assert report()['sha256']==report()['sha256']

def test_bad_campaign():
    with pytest.raises(ValueError):report(campaign_id='')

def test_invalid_preflight():
    assert report(migration_preflight={'cutover_authorized':True})['migration_preflight']['reason']=='PREFLIGHT_INVALID'

def test_lif_mismatch():
    assert 'LIF_MAPPING_MISSING' in report(target_lifs=lif('n2',True)+[{'lif_id':'lif2','svm':'svm1','protocol':'SMB','home_node':'n1','current_node':'n1','operational':True,'session_revalidated':True}])['blockers']
from odmm_qualification_v2094 import migration_runbook

def test_runbook_default_blocked():
    r=migration_runbook({'reason':'OFFLINE_MIGRATION_AND_VAULT_REKEY_REQUIRED'})
    assert r['status']=='BLOCKED' and not r['cutover_authorized']

def test_runbook_complete_still_no_cutover():
    r=migration_runbook({'reason':'OFFLINE_MIGRATION_AND_VAULT_REKEY_REQUIRED'},backup_verified=True,vault_refs_verified=True,rotation_verified=True,independent_approval=True)
    assert r['status']=='READY_FOR_MANUAL_REVIEW' and r['cutover_authorized'] is False

def test_runbook_bad_preflight():
    r=migration_runbook({'reason':'DATABASE_MISSING'},backup_verified=True,vault_refs_verified=True,rotation_verified=True,independent_approval=True)
    assert r['status']=='BLOCKED'
