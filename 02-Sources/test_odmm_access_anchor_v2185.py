import sqlite3
import pytest
from odmm_access_audit_v2184 import append_campaign, AuditError, digest
from odmm_access_anchor_v2185 import append_anchored, verify_anchored, reconcile_anchored

def campaign():
    report={'cases':[],'cutover_authorized':False,'nas_qualified':False,'dedicated_account_attested':False}
    return {'report':report,'sha256':digest(report)}

def test_roundtrip(tmp_path):
    a,b=tmp_path/'audit.db',tmp_path/'anchor.db'
    first=append_anchored(a,b,campaign())
    assert append_anchored(a,b,campaign(),expected_head=first['head'])['seq']==2
    assert verify_anchored(a,b)['entries']==2

def test_stale_writer(tmp_path):
    a,b=tmp_path/'a.db',tmp_path/'b.db';append_anchored(a,b,campaign())
    with pytest.raises(AuditError,match='STALE_HEAD'):append_anchored(a,b,campaign(),expected_head='0'*64)

def test_unanchored_commit_requires_approval(tmp_path):
    a,b=tmp_path/'a.db',tmp_path/'b.db';first=append_anchored(a,b,campaign())
    pending=append_campaign(a,campaign(),expected_head=first['head'])
    with pytest.raises(AuditError,match='ANCHOR_MISMATCH'):verify_anchored(a,b)
    with pytest.raises(AuditError,match='ANCHOR_MISMATCH'):append_anchored(a,b,campaign())
    with pytest.raises(AuditError,match='OPERATOR_APPROVAL'):reconcile_anchored(a,b,expected_audit_head=pending['head'])
    assert reconcile_anchored(a,b,approved=True,expected_audit_head=pending['head'])['entries']==2
    assert verify_anchored(a,b)['entries']==2

def test_anchor_tamper(tmp_path):
    a,b=tmp_path/'a.db',tmp_path/'b.db';append_anchored(a,b,campaign())
    db=sqlite3.connect(b);db.execute("UPDATE anchor SET head=?",('f'*64,));db.commit();db.close()
    with pytest.raises(AuditError,match='ANCHOR_MISMATCH'):verify_anchored(a,b)

def test_conflicting_reconciliation(tmp_path):
    a,b=tmp_path/'a.db',tmp_path/'b.db';append_anchored(a,b,campaign())
    db=sqlite3.connect(b);db.execute("UPDATE anchor SET head=?",('f'*64,));db.commit();db.close()
    with pytest.raises(AuditError,match='CONFLICTING_HEAD'):reconcile_anchored(a,b,approved=True,expected_audit_head=verify_audit_head(a))

def verify_audit_head(a):
    from odmm_access_audit_v2184 import verify_audit
    return verify_audit(a)['head']

def test_missing_anchor(tmp_path):
    with pytest.raises(AuditError,match='ANCHOR_MISSING'):verify_anchored(tmp_path/'a',tmp_path/'b')
