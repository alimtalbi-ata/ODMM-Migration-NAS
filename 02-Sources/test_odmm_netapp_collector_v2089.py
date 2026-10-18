from datetime import datetime,timezone,timedelta
import pytest
from odmm_netapp_collector_v2089 import sign_envelope,verify_envelope,assess_signed_recipe,CollectorError
from odmm_netapp_evidence_v2088 import digest
NOW=datetime(2026,10,15,12,tzinfo=timezone.utc)
KEY=b'k'*32
RING={('agent1','k1'):KEY,('agent2','k1'):b'x'*32}
def env(payload=None,collector='agent1',nonce='n1',key=KEY,issued=None):
    return sign_envelope([] if payload is None else payload,collector_id=collector,key_id='k1',secret=key,nonce=nonce,issued_at=(issued or NOW).isoformat())
def test_valid():assert verify_envelope(env(),keyring=RING,used_nonces=set(),now=NOW)==[]
def test_tamper():
    e=env();e['payload']=[1]
    with pytest.raises(CollectorError,match='MAC_MISMATCH'):verify_envelope(e,keyring=RING,used_nonces=set(),now=NOW)
def test_replay():
    used=set();verify_envelope(env(),keyring=RING,used_nonces=used,now=NOW)
    with pytest.raises(CollectorError,match='REPLAY_DETECTED'):verify_envelope(env(),keyring=RING,used_nonces=used,now=NOW)
def test_expired():
    with pytest.raises(CollectorError,match='ENVELOPE_STALE'):verify_envelope(env(issued=NOW-timedelta(minutes=6)),keyring=RING,used_nonces=set(),now=NOW)
def test_unknown_key():
    with pytest.raises(CollectorError,match='UNKNOWN_COLLECTOR_KEY'):verify_envelope(env(),keyring={},used_nonces=set(),now=NOW)
def test_wrong_key():
    with pytest.raises(CollectorError,match='MAC_MISMATCH'):verify_envelope(env(key=b'z'*32),keyring=RING,used_nonces=set(),now=NOW)
def test_weak_key():
    with pytest.raises(CollectorError,match='WEAK_KEY'):env(key=b'bad')
def test_oversize():
    with pytest.raises(CollectorError,match='ENVELOPE_OVERSIZE'):verify_envelope(env(['x'*200]),keyring=RING,used_nonces=set(),now=NOW,max_bytes=100)
def test_signed_recipe():
    def p(principal):
        r={'collector_id':'agent1','attestation':True,'collected_at':NOW.isoformat(),'evidence_id':principal,'principal_kind':'SID','principal':principal,'protocol':'SMB','path':'/data','operation':'read','allowed':True}
        r['sha256']=digest(r);return r
    result=assess_signed_recipe(env([p('S-1')]),env([p('T-1')],nonce='n2'),[{'kind':'SID','source':'S-1','target':'T-1'}],keyring=RING,used_nonces=set(),now=NOW)
    assert result['blockers']==[] and not result['cutover_authorized']
def test_invalid_recipe():
    result=assess_signed_recipe(env(),env(nonce='n1'),[],keyring=RING,used_nonces=set(),now=NOW)
    assert 'REPLAY_DETECTED' in result['blockers']
