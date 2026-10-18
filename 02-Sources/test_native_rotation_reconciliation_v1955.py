import tempfile,unittest
from pathlib import Path
from unittest.mock import patch
from native_rotation_access_audit import AccessAudit
from native_rotation_audited_execution import execute_audited_rotation
from native_rotation_reconciliation import inspect_rotation_outcome
from native_rotation_portal_binding import build_rotation_endpoint

class ReconciliationV1955(unittest.TestCase):
 def setUp(self):
  self.t=tempfile.TemporaryDirectory();self.addCleanup(self.t.cleanup)
  self.audit=AccessAudit(Path(self.t.name)/'audit.db',key=b'z'*32)
 def call(self,rid='req1',effect=lambda:42):
  return execute_audited_rotation(audit=self.audit,request_id=rid,subject='exec',target_key_id='key2',authorize=lambda:True,execute=effect)
 def test_absent(self):self.assertEqual(inspect_rotation_outcome(audit=self.audit,request_id='none')['state'],'NOT_ADMITTED')
 def test_complete_is_not_verified(self):
  self.call();self.assertEqual(inspect_rotation_outcome(audit=self.audit,request_id='req1')['state'],'EFFECT_RETURNED_UNVERIFIED')
 def test_uncertain(self):
  with self.assertRaises(RuntimeError):self.call(effect=lambda:(_ for _ in ()).throw(RuntimeError('crash')))
  self.assertEqual(inspect_rotation_outcome(audit=self.audit,request_id='req1')['state'],'OUTCOME_UNCERTAIN')
 def test_pending_interruption(self):
  self.audit.append({'event_id':'admit:req1','event':'rotation_access_allowed'})
  self.assertEqual(inspect_rotation_outcome(audit=self.audit,request_id='req1')['state'],'ADMITTED_PENDING_RECONCILIATION')
 def test_invalid_id(self):
  with self.assertRaises(ValueError):inspect_rotation_outcome(audit=self.audit,request_id='../oops')
 def test_tamper_refused(self):
  import sqlite3
  self.call()
  with sqlite3.connect(self.audit.path) as c:c.execute("UPDATE access_audit SET signature='bad' WHERE seq=1")
  with self.assertRaises(Exception):inspect_rotation_outcome(audit=self.audit,request_id='req1')
 def test_provider_pair_required(self):
  with self.assertRaisesRegex(ValueError,'TOGETHER'):
   build_rotation_endpoint(db='db',authorization=lambda r:True,secrets_provider=lambda:{},audit=self.audit)
 def test_provider_callable_required(self):
  with self.assertRaisesRegex(ValueError,'SUBJECT_PROVIDER'):
   build_rotation_endpoint(db='db',authorization=lambda r:True,secrets_provider=lambda:{},audit=self.audit,subject_provider='bad')
 def test_no_retry(self):
  self.call()
  with self.assertRaisesRegex(ValueError,'ALREADY_ADMITTED'):self.call()
 def test_no_effect_if_audit_corrupt(self):
  import sqlite3
  self.call()
  with sqlite3.connect(self.audit.path) as c:c.execute("UPDATE access_audit SET signature='bad' WHERE seq=1")
  calls=[]
  with self.assertRaises(Exception):self.call('req2',lambda:calls.append(1))
  self.assertFalse(calls)
