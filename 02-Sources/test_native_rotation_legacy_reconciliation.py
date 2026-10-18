import sqlite3, tempfile, unittest
from pathlib import Path
from native_benchmark_cockpit_adapter import _canonical, _mac
from native_rotation_revocation_chain import initialize_revocations, verify_revocations
from native_rotation_legacy_reconciliation import reconcile_legacy_revocations

class LegacyReconciliationTests(unittest.TestCase):
 def setUp(self):
  self.t=tempfile.TemporaryDirectory();self.addCleanup(self.t.cleanup)
  self.db=Path(self.t.name)/'r.db';self.gateway=b'g'*32;self.key=b'k'*32
  self.head=initialize_revocations(self.db,revocation_key=self.key)['head']
  with sqlite3.connect(self.db) as c:
   c.execute('CREATE TABLE epoch_review_revocations(request_id TEXT PRIMARY KEY,payload_json TEXT NOT NULL,gateway_mac TEXT NOT NULL,recorded_ns INTEGER NOT NULL)')
 def add(self,rid='r1',tamper=False):
  p={'request_id':rid,'decision':'DENY','requester':'alice'}
  with sqlite3.connect(self.db) as c:c.execute('INSERT INTO epoch_review_revocations VALUES(?,?,?,?)',(rid,_canonical(p).decode(),'bad' if tamper else _mac(self.gateway,p),123))
 def call(self,**kwargs):
  return reconcile_legacy_revocations(self.db,gateway_key=self.gateway,revocation_key=self.key,expected_head=self.head,**kwargs)
 def test_empty(self):self.assertEqual(self.call()['missing_count'],0)
 def test_preview_no_write(self):
  self.add();self.assertEqual(self.call()['missing_count'],1)
  self.assertEqual(verify_revocations(self.db,revocation_key=self.key,expected_head=self.head)['count'],0)
 def test_explicit_import(self):
  self.add();r=self.call(apply=True);self.assertEqual(r['missing_count'],1)
  self.assertEqual(verify_revocations(self.db,revocation_key=self.key,expected_head=r['new_head'])['count'],1)
 def test_idempotent(self):
  self.add();r=self.call(apply=True);self.head=r['new_head'];self.assertEqual(self.call(apply=True)['missing_count'],0)
 def test_tampered_signature(self):
  self.add(tamper=True)
  with self.assertRaisesRegex(ValueError,'UNVERIFIED'):self.call(apply=True)
 def test_stale_head(self):
  self.add()
  with self.assertRaisesRegex(ValueError,'ANCHOR_MISMATCH'):reconcile_legacy_revocations(self.db,gateway_key=self.gateway,revocation_key=self.key,expected_head='f'*64,apply=True)
 def test_wrong_gateway(self):
  self.add()
  with self.assertRaisesRegex(ValueError,'UNVERIFIED'):reconcile_legacy_revocations(self.db,gateway_key=b'z'*32,revocation_key=self.key,expected_head=self.head)
 def test_missing_legacy_table(self):
  with sqlite3.connect(self.db) as c:c.execute('DROP TABLE epoch_review_revocations')
  with self.assertRaisesRegex(ValueError,'MISSING'):self.call()
 def test_no_partial_import(self):
  self.add('a');self.add('b',tamper=True)
  with self.assertRaisesRegex(ValueError,'UNVERIFIED'):self.call(apply=True)
  self.assertEqual(verify_revocations(self.db,revocation_key=self.key,expected_head=self.head)['count'],0)

class GateReconciliationTests(unittest.TestCase):
 def test_unreconciled_legacy_blocks_gate(self):
  from test_native_rotation_unified_gate import UnifiedGateTests
  fixture=UnifiedGateTests(methodName='test_success')
  fixture.setUp()
  try:
   with sqlite3.connect(fixture.db) as c:
    c.execute('INSERT INTO epoch_review_revocations VALUES (?,?,?,?)',('unrelated','{}','bogus',123))
   with self.assertRaisesRegex(ValueError,'LEGACY_REVOCATIONS_NOT_RECONCILED'):
    fixture.call()
  finally:
   fixture.tearDown()
