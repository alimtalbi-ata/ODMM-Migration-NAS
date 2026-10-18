from datetime import datetime,timezone
from concurrent.futures import ThreadPoolExecutor
import pytest
from odmm_collector_registry_v2090 import CollectorRegistry
from odmm_netapp_collector_v2089 import sign_envelope,CollectorError
NOW=datetime(2026,10,15,12,tzinfo=timezone.utc)
KEY=b'X'*32
def envelope(nonce='unique',kid='k1'):
    return sign_envelope({'ok':True},collector_id='agent',key_id=kid,secret=KEY,nonce=nonce,issued_at=NOW.isoformat())
def test_persistent_replay(tmp_path):
    p=tmp_path/'db.sqlite';r=CollectorRegistry(p);r.register_key('agent','k1',KEY)
    assert r.verify_once(envelope(),now=NOW)=={'ok':True}
    with pytest.raises(CollectorError,match='REPLAY_DETECTED'):CollectorRegistry(p).verify_once(envelope(),now=NOW)
def test_concurrent_single_accept(tmp_path):
    r=CollectorRegistry(tmp_path/'db');r.register_key('agent','k1',KEY)
    def work(_):
        try:r.verify_once(envelope(),now=NOW);return 'OK'
        except CollectorError as exc:return str(exc)
    with ThreadPoolExecutor(max_workers=6) as pool:results=list(pool.map(work,range(6)))
    assert results.count('OK')==1 and results.count('REPLAY_DETECTED')==5
def test_rotation_and_revocation(tmp_path):
    r=CollectorRegistry(tmp_path/'db');r.register_key('agent','k1',KEY);r.register_key('agent','k2',KEY)
    r.revoke_key('agent','k1')
    with pytest.raises(CollectorError,match='UNKNOWN_OR_REVOKED_KEY'):r.verify_once(envelope(),now=NOW)
    assert r.verify_once(envelope('n2','k2'),now=NOW)=={'ok':True}
def test_duplicate_key_id(tmp_path):
    r=CollectorRegistry(tmp_path/'db');r.register_key('agent','k1',KEY)
    with pytest.raises(CollectorError,match='KEY_ID_ALREADY_USED'):r.register_key('agent','k1',KEY)
def test_audit_tampering(tmp_path):
    r=CollectorRegistry(tmp_path/'db');r.register_key('agent','k1',KEY);r.verify_once(envelope(),now=NOW)
    rows=r.export_audit();assert r.verify_audit(rows)
    rows[0]['details']['kid']='evil';assert not r.verify_audit(rows)
def test_invalid_mac_does_not_consume_nonce(tmp_path):
    r=CollectorRegistry(tmp_path/'db');r.register_key('agent','k1',KEY)
    e=envelope();e['payload']['ok']=False
    with pytest.raises(CollectorError,match='MAC_MISMATCH'):r.verify_once(e,now=NOW)
    assert r.verify_once(envelope(),now=NOW)=={'ok':True}
