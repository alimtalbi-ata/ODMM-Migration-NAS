import copy
import tempfile
import time
import unittest
from pathlib import Path
from native_cockpit_audit_epochs import transact_epoch,verify_epochs
from native_cockpit_review_decisions import sign_review,record_review,verify_reviews

class ReviewDecisionTests(unittest.TestCase):
 def setUp(self):
  self.t=tempfile.TemporaryDirectory();self.addCleanup(self.t.cleanup)
  self.db=Path(self.t.name)/'audit.sqlite';self.keys={'old':b'A'*32};self.gw=b'G'*32;self.lk=b'L'*32
  self.state=transact_epoch(self.db,keys=self.keys,operation='START',key_id='old')
  self.now=time.time_ns()
  self.signed=sign_review(gateway_key=self.gw,request_id='request-123',requester='alice',reviewer='bob',decision='APPROVE',expected_head=self.state['head'],issued_ns=self.now-100,expires_ns=self.now+10000000000)
 def record(self,signed=None,**kw):return record_review(self.db,keys=self.keys,signed=self.signed if signed is None else signed,gateway_key=kw.get('gateway_key',self.gw),ledger_key=kw.get('ledger_key',self.lk),now_ns=kw.get('now_ns',self.now))
 def test_approve_records_without_rotation(self):
  r=self.record();self.assertEqual(r['decision'],'APPROVE');self.assertFalse(r['rotation_applied']);self.assertEqual(verify_epochs(self.db,keys=self.keys)['active_key_id'],'old')
 def test_deny_records_without_rotation(self):
  s=sign_review(gateway_key=self.gw,request_id='request-456',requester='alice',reviewer='bob',decision='DENY',expected_head=self.state['head'],issued_ns=self.now-100,expires_ns=self.now+10000000000)
  self.assertEqual(self.record(s)['decision'],'DENY')
 def test_replay(self):
  self.record()
  with self.assertRaises(ValueError):self.record()
 def test_expired(self):
  with self.assertRaises(ValueError):self.record(now_ns=self.now+20000000000)
 def test_not_yet_valid(self):
  with self.assertRaises(ValueError):self.record(now_ns=self.now-200)
 def test_wrong_gateway(self):
  with self.assertRaises(ValueError):self.record(gateway_key=b'X'*32)
 def test_tampered_payload(self):
  s=copy.deepcopy(self.signed);s['payload']['decision']='DENY'
  with self.assertRaises(ValueError):self.record(s)
 def test_self_review(self):
  with self.assertRaises(ValueError):sign_review(gateway_key=self.gw,request_id='request-123',requester='alice',reviewer='alice',decision='DENY',expected_head=self.state['head'],issued_ns=self.now,expires_ns=self.now+1)
 def test_stale_epoch(self):
  transact_epoch(self.db,keys=self.keys,operation='EVENT',event_digest='f'*64)
  with self.assertRaises(ValueError):self.record()
 def test_verify_and_trusted_head(self):
  r=self.record();self.assertEqual(verify_reviews(self.db,ledger_key=self.lk,trusted_head=r['head'])['count'],1)
  with self.assertRaises(ValueError):verify_reviews(self.db,ledger_key=self.lk,trusted_head='0'*64)
 def test_wrong_ledger_key(self):
  self.record()
  with self.assertRaises(ValueError):verify_reviews(self.db,ledger_key=b'Z'*32)
 def test_tampered_ledger(self):
  import sqlite3
  self.record()
  with sqlite3.connect(self.db) as c:c.execute("UPDATE epoch_review_decisions SET decision='DENY'")
  with self.assertRaises(ValueError):verify_reviews(self.db,ledger_key=self.lk)
 def test_second_decision_chain(self):
  self.record()
  s=sign_review(gateway_key=self.gw,request_id='request-456',requester='alice',reviewer='bob',decision='DENY',expected_head=self.state['head'],issued_ns=self.now-100,expires_ns=self.now+10000000000)
  self.record(s)
  self.assertEqual(verify_reviews(self.db,ledger_key=self.lk)['count'],2)
