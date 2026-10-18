import tempfile, unittest
from pathlib import Path
from collector_provenance import sign_capture,ProvenanceRegistry,EvidenceRejected
KEY=b'k'*32
CAP={'protocol':'NFSv4','side':'source','path':'/data/f','collector':'collector-a','identity_context':'realm','acl_raw_sha256':'a'*64,'complete':True}
class ProvenanceTests(unittest.TestCase):
 def setUp(self):
  self.tmp=tempfile.TemporaryDirectory(); self.path=str(Path(self.tmp.name)/'proof.db'); self.reg=ProvenanceRegistry(self.path,{'collector-a':KEY}); self.env=sign_capture(CAP,'collector-a','nonce-000000000001',1000,KEY)
 def tearDown(self): self.reg.close(); self.tmp.cleanup()
 def test_valid_envelope(self): self.assertFalse(self.reg.verify_and_record(self.env,now=1000)['effective_access_certified'])
 def test_replay_rejected(self):
  self.reg.verify_and_record(self.env,now=1000)
  with self.assertRaises(EvidenceRejected): self.reg.verify_and_record(self.env,now=1000)
 def test_replay_after_reopen(self):
  self.reg.verify_and_record(self.env,now=1000); self.reg.close(); self.reg=ProvenanceRegistry(self.path,{'collector-a':KEY})
  with self.assertRaises(EvidenceRejected): self.reg.verify_and_record(self.env,now=1000)
 def test_tamper_rejected(self):
  self.env['capture']['path']='/changed'
  with self.assertRaises(EvidenceRejected): self.reg.verify_and_record(self.env,now=1000)
 def test_stale_rejected(self):
  with self.assertRaises(EvidenceRejected): self.reg.verify_and_record(self.env,now=2000)
 def test_unknown_collector(self):
  self.env['collector_id']='untrusted'
  with self.assertRaises(EvidenceRejected): self.reg.verify_and_record(self.env,now=1000)
 def test_weak_key_rejected(self):
  with self.assertRaises(EvidenceRejected): sign_capture(CAP,'collector-a','nonce-000000000001',1000,b'x')
if __name__=='__main__': unittest.main()
