import copy
import pytest
from odmm_ldap_membership_v2192 import _hash
from odmm_authenticated_campaign_v2194 import reconcile_directory_campaign, CampaignDirectoryMismatch

def fixture():
    d={'schema':'odmm.ldap-membership.v2192','transport_authenticated':True,'directory_authenticated':True,'transport_mode':'LDAPS_CERT_REQUIRED','observed_at':100,'accounts':{'cn=alice,dc=example':{'id':'uuid-1'}},'resolved_members':{'cn=ops,dc=example':['uuid-1']}}
    c={'schema':'odmm.group-campaign.v2190','cases':[{'case_id':'1','identity_ref':'alice','group_refs':['ops'],'local_open_outcomes_equal':True}]}
    return {'report':d,'sha256':_hash(d)}, {'report':c,'sha256':_hash(c)}

def run(d,c,**kw):
    return reconcile_directory_campaign(d,c,{'alice':'cn=alice,dc=example'},{'ops':'cn=ops,dc=example'},now=101,**kw)

def test_match_is_not_cutover():
    d,c=fixture(); r=run(d,c); assert r['report']['group_mismatch_count']==0 and r['report']['cutover_authorized'] is False

def test_group_drift_reported():
    d,c=fixture(); d['report']['resolved_members']['cn=ops,dc=example']=[]; d['sha256']=_hash(d['report']); assert run(d,c)['report']['group_mismatch_count']==1

def test_tamper_rejected():
    d,c=fixture(); d['report']['observed_at']=101
    with pytest.raises(CampaignDirectoryMismatch,match='HASH'):run(d,c)

def test_unverified_transport_rejected():
    d,c=fixture(); d['report']['transport_authenticated']=False;d['sha256']=_hash(d['report'])
    with pytest.raises(CampaignDirectoryMismatch,match='UNAUTHENTICATED'):run(d,c)

def test_stale_rejected():
    d,c=fixture()
    with pytest.raises(CampaignDirectoryMismatch,match='STALE'):run(d,c,max_age=0)

def test_ambiguous_mapping_rejected():
    d,c=fixture()
    with pytest.raises(CampaignDirectoryMismatch,match='AMBIGUOUS'):
        reconcile_directory_campaign(d,c,{'alice':'cn=alice,dc=example','bob':'CN=ALICE,DC=EXAMPLE'},{'ops':'cn=ops,dc=example'},now=101)
