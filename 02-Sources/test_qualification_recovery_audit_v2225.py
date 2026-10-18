import json
import pytest
from qualification_recovery_audit_v2225 import append_recovery_audit, verify_recovery_audit
from qualification_review_coordination_v2220 import recover_anchor_supervised
from qualification_review_security_v2217 import review_head, verify_anchor
KEY = b'k' * 32

def test_recovery_audit_chain_and_tamper(tmp_path):
    p=tmp_path/'audit.jsonl'
    head={'schema':'odmm.review.anchor.v2217','count':0,'head_mac':'GENESIS'}
    assert append_recovery_audit(p, KEY, operator='ops1', confirmed_head=head)['count']==1
    assert append_recovery_audit(p, KEY, operator='ops2', confirmed_head=head)['count']==2
    rows=p.read_text().splitlines()
    row=json.loads(rows[0]);row['event']['operator']='attacker'
    p.write_text(json.dumps(row)+'\n'+rows[1]+'\n')
    with pytest.raises(ValueError, match='INTEGRITY'):
        verify_recovery_audit(p,KEY)

def test_supervised_recovery_writes_audit(tmp_path):
    db=tmp_path/'db.sqlite';anchor=tmp_path/'anchor.json';audit=tmp_path/'audit.jsonl'
    head=review_head(db,KEY)
    result=recover_anchor_supervised(db,anchor,secret=KEY,expected_head_mac=head['head_mac'],expected_count=head['count'],audit_path=audit,operator='operator1')
    assert result['cutover_authorized'] is False
    assert verify_anchor(db,anchor,KEY)
    assert verify_recovery_audit(audit,KEY)['count']==1

def test_missing_operator_does_not_reanchor(tmp_path):
    db=tmp_path/'db.sqlite';anchor=tmp_path/'anchor.json';audit=tmp_path/'audit.jsonl'
    head=review_head(db,KEY)
    with pytest.raises(ValueError, match='OPERATOR'):
        recover_anchor_supervised(db,anchor,secret=KEY,expected_head_mac=head['head_mac'],expected_count=0,audit_path=audit)
    assert not anchor.exists()

def test_tampered_audit_blocks_recovery(tmp_path):
    db=tmp_path/'db.sqlite';anchor=tmp_path/'anchor.json';audit=tmp_path/'audit.jsonl'
    head=review_head(db,KEY)
    audit.write_text('garbage\n')
    with pytest.raises(ValueError, match='INTEGRITY'):
        recover_anchor_supervised(db,anchor,secret=KEY,expected_head_mac=head['head_mac'],expected_count=0,audit_path=audit,operator='ops')
    assert not anchor.exists()
