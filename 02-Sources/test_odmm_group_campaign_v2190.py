import hashlib
import json
import pytest
from odmm_group_campaign_v2190 import build_group_campaign, GroupCampaignError
from odmm_group_membership_v2189 import GroupPreflightError

def record(user='alice', groups=('operators','admins'), equal=True):
    r = {'case_id':'case-1','direction':'NetApp->FlashBlade','relative_path':'a',
         'execution_euid':1000,'execution_egid':1000,'source_outcome':'ALLOWED',
         'target_outcome':'ALLOWED' if equal else 'DENIED',
         'source_evidence_sha256':'a'*64,'target_evidence_sha256':'b'*64,
         'local_open_outcomes_equal':equal,'cutover_authorized':False,
         'effective_nas_acl_verified':False,'ad_ldap_authentication_verified':False}
    return {'report':r,'sha256':hashlib.sha256(json.dumps(r,sort_keys=True,separators=(',',':'),ensure_ascii=True).encode()).hexdigest(),
            'identity_ref':user,'group_refs':list(groups)}

def test_nested_membership_and_digest():
    a=build_group_campaign([record()],{'admins':['operators'],'operators':['alice']},['alice'])
    assert a['report']['case_count']==1
    assert a['report']['cutover_authorized'] is False
    assert a==build_group_campaign([record()],{'operators':['alice'],'admins':['operators']},['alice'])

def test_mismatch_retained():
    a=build_group_campaign([record(equal=False)],{'admins':['operators'],'operators':['alice']},['alice'])
    assert a['report']['local_outcome_mismatch_count']==1

@pytest.mark.parametrize('user,groups,error',[
    ('unknown',('admins','operators'),'UNRESOLVED_IDENTITY'),
    ('alice',('operators',),'GROUP_MEMBERSHIP_MISMATCH'),
    ('alice',('admins','operators','extra'),'GROUP_MEMBERSHIP_MISMATCH'),
])
def test_unattested_labels_fail(user,groups,error):
    with pytest.raises(GroupCampaignError,match=error):
        build_group_campaign([record(user,groups)],{'admins':['operators'],'operators':['alice']},['alice'])

def test_cycle_fails():
    with pytest.raises(GroupPreflightError):
        build_group_campaign([record()],{'admins':['operators'],'operators':['admins']},['alice'])

def test_modified_evidence_fails():
    r=record();r['report']['source_outcome']='DENIED'
    with pytest.raises(ValueError):
        build_group_campaign([r],{'admins':['operators'],'operators':['alice']},['alice'])
