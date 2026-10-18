import hashlib
import pytest
from odmm_campaign_history_v2096 import CampaignHistory,canonical
from odmm_campaign_anchor_v2097 import create_anchor,verify_anchor,export_verified_history,compare_versions

KEY=b'K'*32
RESOLVER=lambda kid: KEY if kid=='vault-key-1' else None

def report(n,blockers=None):
    d={'schema':'odmm.campaign.v2095','campaign_id':'demo','status':'BLOCKED','cutover_authorized':False,'report_count':n,'submitted_count':n,'reports':[],'blockers':blockers or ['INDEPENDENT_APPROVAL_REQUIRED'],'limitations':[]}
    d['sha256']=hashlib.sha256(canonical(d)).hexdigest()
    return d

def history(tmp_path):
    h=CampaignHistory(tmp_path/'history.db')
    h.append(report(1),expected_version=0)
    h.append(report(3,['INDEPENDENT_APPROVAL_REQUIRED','LIF_UNSTABLE']),expected_version=1)
    return h

def test_anchor_and_export(tmp_path):
    h=history(tmp_path);a=create_anchor(h,'demo',key_id='vault-key-1',resolver=RESOLVER)
    assert verify_anchor(h,a,resolver=RESOLVER)['verified']
    e=export_verified_history(h,'demo',key_id='vault-key-1',resolver=RESOLVER)
    assert e['timeline']['version']==2 and not e['anchor']['cutover_authorized']

def test_tamper_mac(tmp_path):
    h=history(tmp_path);a=create_anchor(h,'demo',key_id='vault-key-1',resolver=RESOLVER)
    a['head_hash']='f'*64
    with pytest.raises(ValueError,match='INVALID_ANCHOR_MAC'):verify_anchor(h,a,resolver=RESOLVER)

def test_truncation_detected(tmp_path):
    h=history(tmp_path);a=create_anchor(h,'demo',key_id='vault-key-1',resolver=RESOLVER)
    import sqlite3
    with sqlite3.connect(h.path) as db:db.execute('DELETE FROM campaign_history WHERE version=2')
    with pytest.raises(ValueError,match='HISTORY_ANCHOR_MISMATCH'):verify_anchor(h,a,resolver=RESOLVER)

def test_wrong_key_and_missing_resolver(tmp_path):
    h=history(tmp_path);a=create_anchor(h,'demo',key_id='vault-key-1',resolver=RESOLVER)
    with pytest.raises(ValueError,match='SIGNER_UNAVAILABLE'):verify_anchor(h,a,resolver=lambda kid:None)
    with pytest.raises(ValueError,match='INVALID_ANCHOR_MAC'):verify_anchor(h,a,resolver=lambda kid:b'Z'*32)

def test_diff(tmp_path):
    h=history(tmp_path);d=compare_versions(h,'demo',1,2)
    assert d['report_count_delta']==2 and d['blockers_added']==['LIF_UNSTABLE'] and not d['cutover_authorized']
    with pytest.raises(ValueError,match='INVALID_VERSION_RANGE'):compare_versions(h,'demo',2,1)
    with pytest.raises(ValueError,match='VERSION_NOT_FOUND'):compare_versions(h,'demo',1,3)

def test_no_empty_anchor(tmp_path):
    h=CampaignHistory(tmp_path/'empty.db')
    with pytest.raises(ValueError,match='EMPTY_HISTORY'):create_anchor(h,'demo',key_id='vault-key-1',resolver=RESOLVER)
