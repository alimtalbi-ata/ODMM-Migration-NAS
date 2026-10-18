"""Streaming verification regressions. Author: Abdelhalim Talbi."""
from test_odmm_nas_acl_operations_v2157 import fixture
from test_odmm_nas_acl_recovery_v2151 import signed

def test_streaming_verification_multiple_batches(tmp_path):
    h,store,a=fixture(tmp_path)
    for _ in range(270): h.record(signed())
    assert h.verify_chain() is True

def test_streaming_verification_detects_middle_corruption(tmp_path):
    h,store,a=fixture(tmp_path)
    for _ in range(270): h.record(signed())
    with h._db() as db:
        db.execute('UPDATE acl_audit_history SET digest=? WHERE seq=257',('0'*64,))
    assert h.verify_chain() is False
