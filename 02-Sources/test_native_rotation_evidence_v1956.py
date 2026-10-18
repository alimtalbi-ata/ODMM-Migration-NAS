import tempfile,unittest
from pathlib import Path
from native_rotation_access_audit import AccessAudit
from native_rotation_audited_execution import execute_audited_rotation
from native_rotation_evidence import record_verification
from native_rotation_portal_binding import build_rotation_endpoint,bind_rotation_portal

class EvidenceTests(unittest.TestCase):
 def setUp(self):
  self.t=tempfile.TemporaryDirectory();self.addCleanup(self.t.cleanup)
  self.a=AccessAudit(Path(self.t.name)/'a.db',key=b'x'*32)
  execute_audited_rotation(audit=self.a,request_id='req',subject='operator',target_key_id='target',authorize=lambda:True,execute=lambda:None)
 def verify(self,**kwargs):
  return record_verification(audit=self.a,request_id='req',verifier='independent',observation='MATCHES_EXPECTED',evidence_digest='a'*64,verify_identity=lambda u,r:True,**kwargs)
 def test_record(self):self.assertEqual(self.verify()['retry_allowed'],False)
 def test_persistent(self):
  self.verify();self.assertEqual(len(self.a.export_verified()['events']),3)
 def test_duplicate(self):
  self.verify()
  with self.assertRaisesRegex(ValueError,'ALREADY_RECORDED'):self.verify()
 def test_unauthorized(self):
  with self.assertRaisesRegex(ValueError,'NOT_AUTHORIZED'):record_verification(audit=self.a,request_id='req',verifier='x',observation='INCONCLUSIVE',evidence_digest='a'*64,verify_identity=lambda u,r:False)
 def test_invalid_digest(self):
  with self.assertRaisesRegex(ValueError,'DIGEST'):record_verification(audit=self.a,request_id='req',verifier='x',observation='INCONCLUSIVE',evidence_digest='bad',verify_identity=lambda u,r:True)
 def test_invalid_observation(self):
  with self.assertRaisesRegex(ValueError,'OBSERVATION'):record_verification(audit=self.a,request_id='req',verifier='x',observation='GOOD',evidence_digest='a'*64,verify_identity=lambda u,r:True)
 def test_not_admitted(self):
  with self.assertRaisesRegex(ValueError,'NOT_ADMITTED'):record_verification(audit=self.a,request_id='other',verifier='x',observation='INCONCLUSIVE',evidence_digest='a'*64,verify_identity=lambda u,r:True)
 def test_production_audit_required(self):
  with self.assertRaisesRegex(ValueError,'PRODUCTION_AUDIT_REQUIRED'):build_rotation_endpoint(db='db',authorization=lambda r:True,secrets_provider=lambda:{},production=True)
 def test_production_pin_required(self):
  with self.assertRaisesRegex(ValueError,'PRODUCTION_PIN_REQUIRED'):bind_rotation_portal(object(),db='db',authorization=lambda r:True,secrets_provider=lambda:{},expected_routes_sha256=None,audit=self.a,subject_provider=lambda r:'user',production=True)
 def test_production_provider_pair(self):
  with self.assertRaisesRegex(ValueError,'PRODUCTION_AUDIT_REQUIRED'):build_rotation_endpoint(db='db',authorization=lambda r:True,secrets_provider=lambda:{},audit=self.a,production=True)
