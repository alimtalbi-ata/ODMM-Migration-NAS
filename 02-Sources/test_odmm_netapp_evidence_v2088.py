from datetime import datetime,timezone,timedelta
from odmm_netapp_evidence_v2088 import assess_recipe,digest
NOW=datetime(2026,10,15,12,0,tzinfo=timezone.utc)
MAP=[{'kind':'SID','source':'S-1','target':'T-1'}]
def proof(principal,allowed=True,**kw):
    r={'collector_id':'agent1','attestation':True,'collected_at':NOW.isoformat(),'evidence_id':principal,'principal_kind':'SID','principal':principal,'protocol':'SMB','path':'/data','operation':'read','allowed':allowed}
    r.update(kw);r['sha256']=digest(r);return r
def run(s=None,t=None,m=None,**kw):return assess_recipe([proof('S-1')] if s is None else s,[proof('T-1')] if t is None else t,MAP if m is None else m,trusted_collectors={'agent1'},now=NOW,**kw)
def test_matching():
    r=run();assert r['blockers']==[] and len(r['pairs'])==1 and not r['cutover_authorized']
def test_drift():assert 'EFFECTIVE_ACCESS_DRIFT' in run(t=[proof('T-1',False)])['blockers']
def test_untrusted():assert 'SOURCE_EVIDENCE_UNVERIFIED' in run(s=[proof('S-1',collector_id='evil')])['blockers']
def test_tampered():
    r=proof('S-1');r['allowed']=False;assert 'SOURCE_EVIDENCE_UNVERIFIED' in run(s=[r])['blockers']
def test_stale():assert 'SOURCE_EVIDENCE_UNVERIFIED' in run(s=[proof('S-1',collected_at=(NOW-timedelta(hours=2)).isoformat())])['blockers']
def test_collision():assert 'IDENTITY_COLLISION' in run(m=MAP+[{'kind':'SID','source':'S-2','target':'T-1'}])['blockers']
def test_unmatched():assert 'TARGET_TEST_UNMATCHED' in run(t=[proof('T-1'),proof('T-2')])['blockers']
def test_missing():assert 'SOURCE_EVIDENCE_MISSING' in run(s=[])['blockers']
def test_invalid_protocol():assert 'SOURCE_EVIDENCE_UNVERIFIED' in run(s=[proof('S-1',protocol='UNKNOWN')])['blockers']
