import hashlib, json
import pytest
from odmm_identity_regression_report_v2188 import build_identity_regression_report, IdentityReportError

def canon(x): return json.dumps(x,sort_keys=True,separators=(',', ':'),ensure_ascii=True).encode()
def record(cid='c1', direction='NetApp->OneFS', equal=True, identity='user-test', groups=None):
    r={'case_id':cid,'direction':direction,'relative_path':'dataset/a','execution_euid':1000,'execution_egid':1000,
       'source_outcome':'READABLE','target_outcome':'READABLE' if equal else 'DENIED',
       'source_evidence_sha256':'a'*64,'target_evidence_sha256':'b'*64,
       'local_open_outcomes_equal':equal,'cutover_authorized':False,
       'effective_nas_acl_verified':False,'ad_ldap_authentication_verified':False}
    return {'report':r,'sha256':hashlib.sha256(canon(r)).hexdigest(),'identity_ref':identity,'group_refs':groups or []}
def test_identity_aggregation_and_mismatch():
    out=build_identity_regression_report([record(),record('c2','OneFS->NetApp',False,groups=['grp-ops'])])['report']
    assert out['case_count']==2 and out['identity_count']==1
    assert out['local_outcome_mismatch_count']==1
    assert out['identity_summaries'][0]['mismatches'][0]['case_id']=='c2'
    assert out['cutover_authorized'] is False and out['directory_membership_attested'] is False
def test_deterministic_order():
    a=build_identity_regression_report([record('b'),record('a','FlashBlade->NetApp')])
    b=build_identity_regression_report([record('a','FlashBlade->NetApp'),record('b')])
    assert a==b
def test_tampered_worker_evidence_rejected():
    x=record(); x['report']['target_outcome']='DENIED'
    with pytest.raises(IdentityReportError,match='EVIDENCE_DIGEST_MISMATCH'): build_identity_regression_report([x])
def test_duplicate_case_rejected():
    with pytest.raises(IdentityReportError,match='DUPLICATE_OR_INVALID_CASE'): build_identity_regression_report([record(),record()])
def test_bad_direction_rejected():
    with pytest.raises(IdentityReportError,match='INVALID_DIRECTION'): build_identity_regression_report([record(direction='NetApp->Unknown')])
def test_unsafe_qualification_claim_rejected():
    x=record(); x['report']['cutover_authorized']=True; x['sha256']=hashlib.sha256(canon(x['report'])).hexdigest()
    with pytest.raises(IdentityReportError,match='UNSUPPORTED_QUALIFICATION_CLAIM'): build_identity_regression_report([x])
def test_invalid_group_labels_rejected():
    with pytest.raises(IdentityReportError,match='INVALID_GROUP_REFS'): build_identity_regression_report([record(groups=['x','x'])])
def test_empty_input_rejected():
    with pytest.raises(IdentityReportError,match='INVALID_RECORD_COUNT'): build_identity_regression_report([])
