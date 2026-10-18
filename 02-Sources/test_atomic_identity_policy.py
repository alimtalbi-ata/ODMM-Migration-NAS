import tempfile, unittest, sqlite3
from pathlib import Path
from review_identity_policy import IdentityPolicyLedger
from authenticated_review_ledger import sign_assertion
from human_approval_registry import digest, ApprovalError
K=b'k'*32
class TestAtomicIdentityPolicy(unittest.TestCase):
 def setUp(self):
  self.tmp=tempfile.TemporaryDirectory(); self.path=Path(self.tmp.name)/'test.db'
  r={'migration_id':'M1','status':'PENDING_HUMAN_AND_LIVE_VERIFICATION','cutover_authorized':False}
  self.bundle={'report':r,'sha256':digest(r)}
  self.l=IdentityPolicyLedger(self.path,issuer_secret=b'x'*32)
  self.l.provision_key('k1',K,valid_from=0,valid_until=100)
  self.l.set_reviewer('alice','security',active=True,directory_version='v1')
 def tearDown(self): self.l.close(); self.tmp.cleanup()
 def assertion(self, nonce='n1'):
  return sign_assertion(K,migration_id='M1',evidence_hash=self.bundle['sha256'],role='security',reviewer='alice',nonce=nonce,issued_at=10,expires_at=50)
 def submit(self, assertion=None):
  return self.l.record_policy_attested('M1',self.bundle,assertion or self.assertion(),key_id='k1',directory_version='v1',now=11)
 def test_atomic_success(self):
  self.assertFalse(self.submit()['cutover_authorized'])
  self.assertEqual(self.l.db.execute('SELECT COUNT(*) FROM dual_reviews').fetchone()[0],1)
  self.assertEqual(self.l.db.execute('SELECT COUNT(*) FROM review_events').fetchone()[0],1)
  self.assertEqual(self.l.db.execute('SELECT COUNT(*) FROM consumed_review_nonces').fetchone()[0],1)
 def test_invalid_signature_rolls_back_all(self):
  a=self.assertion();a['signature']='0'*64
  with self.assertRaises(ApprovalError): self.submit(a)
  for table in ('dual_reviews','review_events','consumed_review_nonces'):
   self.assertEqual(self.l.db.execute('SELECT COUNT(*) FROM '+table).fetchone()[0],0)
 def test_journal_failure_rolls_back_nonce_and_review(self):
  self.l.db.execute('CREATE TRIGGER block_review_event BEFORE INSERT ON review_events BEGIN SELECT RAISE(ABORT,"simulated failure"); END')
  with self.assertRaises(sqlite3.DatabaseError): self.submit()
  for table in ('dual_reviews','review_events','consumed_review_nonces'):
   self.assertEqual(self.l.db.execute('SELECT COUNT(*) FROM '+table).fetchone()[0],0)
 def test_key_revocation_blocks(self):
  self.l.revoke_key('k1',now=10)
  with self.assertRaises(ApprovalError): self.submit()
  self.assertEqual(self.l.db.execute('SELECT COUNT(*) FROM dual_reviews').fetchone()[0],0)
 def test_reviewer_change_blocks(self):
  self.l.set_reviewer('alice','operations',active=True,directory_version='v2')
  with self.assertRaises(ApprovalError): self.submit()
 def test_no_nested_transaction_and_replay(self):
  self.submit()
  with self.assertRaises(ApprovalError): self.submit()
  self.assertEqual(self.l.db.execute('SELECT COUNT(*) FROM review_events').fetchone()[0],1)
 def test_lock_blocks_external_revoke(self):
  other=sqlite3.connect(self.path,timeout=0.01,isolation_level=None)
  try:
   self.l.db.execute('BEGIN IMMEDIATE')
   with self.assertRaises(sqlite3.OperationalError): other.execute('UPDATE issuer_keys SET revoked_at=10 WHERE key_id="k1"')
  finally:
   self.l.db.execute('ROLLBACK');other.close()
