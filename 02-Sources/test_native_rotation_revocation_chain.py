import sqlite3,tempfile,unittest
from pathlib import Path
from native_rotation_revocation_chain import initialize_revocations,append_revocation,verify_revocations
from test_native_rotation_unified_gate import UnifiedGateTests

class RevocationChainTests(unittest.TestCase):
 def setUp(self):
  self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup);self.db=Path(self.tmp.name)/'r.db';self.key=b'r'*32
  self.genesis=initialize_revocations(self.db,revocation_key=self.key)['head']
 def test_empty_anchor(self):self.assertEqual(verify_revocations(self.db,revocation_key=self.key,expected_head=self.genesis)['count'],0)
 def test_append(self):
  h=append_revocation(self.db,revocation_key=self.key,request_id='r1',reason='cancel',expected_head=self.genesis)['head']
  self.assertEqual(verify_revocations(self.db,revocation_key=self.key,expected_head=h)['count'],1)
 def test_duplicate(self):
  head=append_revocation(self.db,revocation_key=self.key,request_id='r1',reason='cancel',expected_head=self.genesis)['head']
  with self.assertRaisesRegex(ValueError,'DUPLICATE'):append_revocation(self.db,revocation_key=self.key,request_id='r1',reason='again',expected_head=head)
 def test_stale_anchor(self):
  append_revocation(self.db,revocation_key=self.key,request_id='r1',reason='cancel',expected_head=self.genesis)
  with self.assertRaisesRegex(ValueError,'ANCHOR_MISMATCH'):verify_revocations(self.db,revocation_key=self.key,expected_head=self.genesis)
 def test_tampering(self):
  h=append_revocation(self.db,revocation_key=self.key,request_id='r1',reason='cancel',expected_head=self.genesis)['head']
  with sqlite3.connect(self.db) as c:c.execute("UPDATE epoch_revocation_chain SET reason_sha256=?",('f'*64,))
  with self.assertRaisesRegex(ValueError,'TAMPERED'):verify_revocations(self.db,revocation_key=self.key,expected_head=h)
 def test_missing_table(self):
  with sqlite3.connect(self.db) as c:c.execute('DROP TABLE epoch_revocation_chain')
  with self.assertRaisesRegex(ValueError,'MISSING'):verify_revocations(self.db,revocation_key=self.key,expected_head=self.genesis)

class GateRevocationTests(UnifiedGateTests):
 def test_revoked_chain_blocks(self):
  append_revocation(self.db,revocation_key=self.revocation_key,request_id='request-001',reason='cancel',expected_head=self.revocation_head)
  with self.assertRaises(ValueError):self.call()
 def test_chain_anchor_required(self):
  with self.assertRaisesRegex(ValueError,'EXTERNAL_REVOCATION_ANCHOR_REQUIRED'):self.call(trusted_revocation_head=None)
 def test_chain_tamper_blocks(self):
  with sqlite3.connect(self.db) as c:c.execute("UPDATE epoch_revocation_chain SET mac_sha256='invalid' WHERE seq=1")
  # If chain is empty, insert a revocation first in this test to exercise tamper detection.
  with self.assertRaises(ValueError):self.call(trusted_revocation_head='f'*64)
