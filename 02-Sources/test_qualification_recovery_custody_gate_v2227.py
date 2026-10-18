import json
import pytest
from qualification_review_coordination_v2220 import recover_anchor_supervised
from qualification_review_security_v2217 import review_head, verify_anchor
from qualification_recovery_custody_v2226 import export_custody, verify_custody
from qualification_recovery_audit_v2225 import verify_recovery_audit
KEY=b'k'*32

def setup(tmp_path):
    db=tmp_path/'db.sqlite'; anchor=tmp_path/'anchor'; audit=tmp_path/'audit'; custody=tmp_path/'custody'
    head=review_head(db,KEY)
    return db,anchor,audit,custody,head

def recover(parts):
    db,anchor,audit,custody,head=parts
    return recover_anchor_supervised(db,anchor,secret=KEY,expected_head_mac=head['head_mac'],expected_count=head['count'],audit_path=audit,operator='operator',custody_path=custody)

def test_missing_custody_fails_closed(tmp_path):
    parts=setup(tmp_path)
    with pytest.raises(ValueError,match='CUSTODY'):recover(parts)
    assert not parts[1].exists()

def test_success_and_custody_updated(tmp_path):
    parts=setup(tmp_path);export_custody(parts[2],parts[3],KEY)
    assert recover(parts)['cutover_authorized'] is False
    assert verify_custody(parts[2],parts[3],KEY)['checkpoint_count']==1
    assert verify_anchor(parts[0],parts[1],KEY)

def test_tampered_checkpoint_blocks_without_append(tmp_path):
    parts=setup(tmp_path);export_custody(parts[2],parts[3],KEY)
    data=json.loads(parts[3].read_text());data['payload']['count']=5;parts[3].write_text(json.dumps(data))
    with pytest.raises(ValueError,match='CUSTODY'):recover(parts)
    assert verify_recovery_audit(parts[2],KEY)['count']==0
    assert not parts[1].exists()

def test_export_failure_blocks_anchor(tmp_path,monkeypatch):
    parts=setup(tmp_path);export_custody(parts[2],parts[3],KEY)
    import qualification_review_coordination_v2220 as mod
    def fail(*args):raise OSError('offline')
    monkeypatch.setattr(mod,'export_custody',fail)
    with pytest.raises(OSError,match='offline'):recover(parts)
    assert verify_recovery_audit(parts[2],KEY)['count']==1
    assert not parts[1].exists()

def test_custody_without_audit_rejected(tmp_path):
    db,anchor,audit,custody,head=setup(tmp_path)
    with pytest.raises(ValueError,match='REQUIRES_AUDIT'):
        recover_anchor_supervised(db,anchor,secret=KEY,expected_head_mac=head['head_mac'],expected_count=0,custody_path=custody)
