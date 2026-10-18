import copy
import sqlite3
import tempfile
import time
import unittest
from pathlib import Path
from native_cockpit_audit_epochs import transact_epoch,verify_epochs
from native_cockpit_review_decisions import sign_review,record_review
from native_cockpit_review_gate import revoke_review,apply_review_gated_rotation

class ReviewGateTests(unittest.TestCase):
 def setUp(self):
  self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup)
  self.db=Path(self.tmp.name)/'audit.sqlite';self.keys={'old':b'A'*32,'new':b'B'*32}
  self.gw=b'G'*32;self.lk=b'L'*32;self.now=time.time_ns()
  self.state=transact_epoch(self.db,keys=self.keys,operation='START',key_id='old')
 def signed(self,decision='APPROVE',request_id='request-123',head=None,expires=None):
  return sign_review(gateway_key=self.gw,request_id=request_id,requester='alice',reviewer='bob',decision=decision,expected_head=head or self.state['head'],issued_ns=self.now-10000,expires_ns=expires or self.now+10000000000)
 def record(self,s=None):
  return record_review(self.db,keys=self.keys,signed=s or self.signed(),gateway_key=self.gw,ledger_key=self.lk,now_ns=self.now)
 def rotate(self,**kw):
  return apply_review_gated_rotation(self.db,keys=self.keys,request_id=kw.get('request_id','request-123'),new_key_id='new',gateway_key=kw.get('gateway_key',self.gw),ledger_key=kw.get('ledger_key',self.lk),now_ns=kw.get('now_ns',self.now))
 def revoke(self,s=None):
  return revoke_review(self.db,keys=self.keys,signed_deny=s or self.signed('DENY'),gateway_key=self.gw,ledger_key=self.lk,now_ns=self.now)
 def test_valid(self):
  self.record();self.assertTrue(self.rotate()['rotation_applied']);self.assertEqual(verify_epochs(self.db,keys=self.keys)['active_key_id'],'new')
 def test_no_review(self):
  with self.assertRaises(ValueError):self.rotate()
 def test_denied(self):
  self.record(self.signed('DENY'))
  with self.assertRaises(ValueError):self.rotate()
 def test_revoked(self):
  self.record();self.revoke()
  with self.assertRaises(ValueError):self.rotate()
 def test_revoke_replay(self):
  self.record();self.revoke()
  with self.assertRaises(sqlite3.IntegrityError):self.revoke()
 def test_revoke_without_review(self):
  with self.assertRaises(ValueError):self.revoke()
 def test_revoke_after_rotation(self):
  self.record();self.rotate()
  with self.assertRaises(ValueError):self.revoke()
 def test_replay(self):
  self.record();self.rotate()
  with self.assertRaises(ValueError):self.rotate()
 def test_expired_at_execution(self):
  self.record()
  with self.assertRaises(ValueError):self.rotate(now_ns=self.now+20000000000)
 def test_stale_epoch(self):
  self.record();transact_epoch(self.db,keys=self.keys,operation='EVENT',event_digest='f'*64)
  with self.assertRaises(ValueError):self.rotate()
 def test_wrong_gateway(self):
  self.record()
  with self.assertRaises(ValueError):self.rotate(gateway_key=b'Z'*32)
 def test_wrong_ledger_key(self):
  self.record()
  with self.assertRaises(ValueError):self.rotate(ledger_key=b'Z'*32)
 def test_revoke_wrong_context(self):
  self.record()
  with self.assertRaises(ValueError):self.revoke(self.signed('DENY',head='f'*64))
 def test_failed_rotation_preserves_epoch(self):
  self.record();self.revoke()
  with self.assertRaises(ValueError):self.rotate()
  self.assertEqual(verify_epochs(self.db,keys=self.keys)['head'],self.state['head'])
