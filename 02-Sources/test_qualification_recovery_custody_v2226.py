import json
import pytest
from qualification_recovery_audit_v2225 import append_recovery_audit
from qualification_recovery_custody_v2226 import export_custody, verify_custody
KEY=b'k'*32
HEAD={'schema':'odmm.review.anchor.v2217','count':0,'head_mac':'GENESIS'}

def test_custody_append_and_prefix(tmp_path):
    a=tmp_path/'audit'; c=tmp_path/'checkpoint'
    append_recovery_audit(a,KEY,operator='a',confirmed_head=HEAD)
    export_custody(a,c,KEY)
    assert verify_custody(a,c,KEY)['verified']
    append_recovery_audit(a,KEY,operator='b',confirmed_head=HEAD)
    assert verify_custody(a,c,KEY)['current_count']==2

def test_rollback_detected(tmp_path):
    a=tmp_path/'audit';c=tmp_path/'checkpoint'
    append_recovery_audit(a,KEY,operator='a',confirmed_head=HEAD)
    first=a.read_bytes()
    append_recovery_audit(a,KEY,operator='b',confirmed_head=HEAD)
    export_custody(a,c,KEY)
    a.write_bytes(first)
    with pytest.raises(ValueError,match='ROLLBACK'):verify_custody(a,c,KEY)

def test_modified_checkpoint_and_missing_checkpoint(tmp_path):
    a=tmp_path/'audit';c=tmp_path/'checkpoint'
    with pytest.raises(ValueError,match='ROLLBACK'):verify_custody(a,c,KEY)
    export_custody(a,c,KEY)
    record=json.loads(c.read_text());record['payload']['count']=3;c.write_text(json.dumps(record))
    with pytest.raises(ValueError,match='ROLLBACK'):verify_custody(a,c,KEY)

def test_divergent_prefix_detected(tmp_path):
    a=tmp_path/'audit';c=tmp_path/'checkpoint'
    append_recovery_audit(a,KEY,operator='first',confirmed_head=HEAD)
    export_custody(a,c,KEY)
    a.unlink()
    append_recovery_audit(a,KEY,operator='other',confirmed_head=HEAD)
    append_recovery_audit(a,KEY,operator='third',confirmed_head=HEAD)
    with pytest.raises(ValueError,match='ROLLBACK'):verify_custody(a,c,KEY)
