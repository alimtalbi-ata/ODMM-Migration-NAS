import copy
import pytest
from odmm_ldap_membership_v2192 import _hash
from odmm_directory_audit_v2195 import audit_directory_campaign
from odmm_access_anchor_v2185 import verify_anchored
from odmm_access_audit_v2184 import AuditError

def inputs():
    d={'schema':'odmm.ldap-membership.v2192','transport_authenticated':True,'directory_authenticated':True,'transport_mode':'LDAPS_CERT_REQUIRED','observed_at':100,'accounts':{'cn=a,dc=x':{'id':'u1'}},'resolved_members':{'cn=g,dc=x':['u1']}}
    c={'schema':'odmm.group-campaign.v2190','cases':[{'case_id':'case-1','identity_ref':'a','group_refs':['g'],'local_open_outcomes_equal':True}]}
    return {'report':d,'sha256':_hash(d)},{'report':c,'sha256':_hash(c)}

def run(tmp_path,d=None,c=None,**kw):
    if d is None:d,c=inputs()
    return audit_directory_campaign(d,c,{'a':'cn=a,dc=x'},{'g':'cn=g,dc=x'},now=101,audit_path=tmp_path/'audit.db',anchor_path=tmp_path/'anchor.db',**kw)

def test_anchored_success(tmp_path):
    r=run(tmp_path);assert r['cutover_authorized'] is False
    assert verify_anchored(tmp_path/'audit.db',tmp_path/'anchor.db')['entries']==1

def test_mismatch_audited_not_authorized(tmp_path):
    d,c=inputs();d['report']['resolved_members']['cn=g,dc=x']=[];d['sha256']=_hash(d['report'])
    r=run(tmp_path,d,c);assert r['evidence']['report']['group_mismatch_count']==1
    assert r['cutover_authorized'] is False

def test_duplicate_cases_fail_before_write(tmp_path):
    d,c=inputs();c['report']['cases'].append(copy.deepcopy(c['report']['cases'][0]));c['sha256']=_hash(c['report'])
    with pytest.raises(AuditError,match='INVALID_CASE_SCOPE'):run(tmp_path,d,c)
    assert not (tmp_path/'audit.db').exists()

def test_stale_head_blocks_append(tmp_path):
    run(tmp_path)
    with pytest.raises(AuditError,match='STALE_HEAD'):run(tmp_path,expected_head='0'*64)
    assert verify_anchored(tmp_path/'audit.db',tmp_path/'anchor.db')['entries']==1
