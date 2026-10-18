import tempfile
from pathlib import Path
import pytest
from odmm_nas_acl_history_v2149 import AuditHistory
from odmm_nas_acl_recovery_v2151 import RecoverableAnchoredHistory
from odmm_nas_acl_export_v2148 import canonical
import hashlib,hmac

KEY=b'k'*32

def fixture():
    tmp=tempfile.TemporaryDirectory()
    h=AuditHistory(Path(tmp.name)/'audit.db',KEY)
    remote={'value':None,'fail':False}
    def read():return remote['value']
    def write(value):
        if remote['fail']:raise OSError('offline')
        remote['value']=value
    a=RecoverableAnchoredHistory(h,read_anchor=read,write_anchor=write,anchor_key=b'a'*32)
    a.bootstrap_empty()
    return tmp,h,a,remote

def signed():
    base={'schema':'odmm.nas.acl.audit.export.v2148','protocol':'NFSv4','reports':[],'cutover_authorized':False}
    base['payload_sha256']=hashlib.sha256(canonical(base)).hexdigest()
    return {**base,'signature':hmac.new(KEY,canonical(base),hashlib.sha256).hexdigest()}

def test_consistent():
    tmp,h,a,r=fixture()
    try:assert a.inspect_recovery()['state']=='CONSISTENT'
    finally:tmp.cleanup()

def test_split_commit_requires_explicit_recovery():
    tmp,h,a,r=fixture()
    try:
        r['fail']=True
        with pytest.raises(OSError):a.record(signed())
        assert a.inspect_recovery()['state']=='PENDING_ANCHOR'
        assert not a.verify()
        with pytest.raises(ValueError):a.record(signed())
        with pytest.raises(ValueError):a.reconcile_explicit(expected_anchor_seq=0,expected_local_seq=1)
        r['fail']=False
        with pytest.raises(ValueError):a.reconcile_explicit(expected_anchor_seq=0,expected_local_seq=2,approved=True)
        assert a.reconcile_explicit(expected_anchor_seq=0,expected_local_seq=1,approved=True)['state']=='RECOVERED'
        assert a.verify()
    finally:tmp.cleanup()

def test_divergence_blocks_repair():
    tmp,h,a,r=fixture()
    try:
        h.record(signed())
        r['value']['chain_mac']='0'*64
        assert a.inspect_recovery()['state']=='VERIFICATION_ERROR'
        with pytest.raises(ValueError):a.reconcile_explicit(expected_anchor_seq=0,expected_local_seq=1,approved=True)
    finally:tmp.cleanup()

def test_local_rollback_blocks_repair():
    tmp,h,a,r=fixture()
    try:
        a.record(signed())
        with h._db() as db:db.execute('DELETE FROM acl_audit_history')
        assert a.inspect_recovery()['state']=='LOCAL_ROLLBACK'
    finally:tmp.cleanup()
