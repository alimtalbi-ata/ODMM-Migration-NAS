import sqlite3,unittest
from ldaps_crash_reconciliation import CrashReconciliationLedger
from ldaps_durable_target import DurableFencedTarget
from ldaps_rbac_reconciliation import ReconciliationRBAC,ReconciliationRBACError
class C:
 def __init__(self,db):self.db=db
class Tests(unittest.TestCase):
 def setUp(self):
  self.a=sqlite3.connect(':memory:',isolation_level=None);self.b=sqlite3.connect(':memory:',isolation_level=None)
  self.target=DurableFencedTarget(self.b);self.target.advance_epoch('e',1)
  self.rec=CrashReconciliationLedger(C(self.a),self.target);self.rbac=ReconciliationRBAC(self.rec)
  self.rbac.set_reviewer('sec','SECURITY',active=True);self.rbac.set_reviewer('ops','OPERATIONS',active=True)
  self.rbac.set_reviewer('disabled','OPERATIONS',active=False)
  self.obs=self.rec.record('e','r',observed_at=100)
 def tearDown(self):self.a.close();self.b.close()
 def decide(self,reviewer='sec',**kwargs):
  args=dict(observation_hash=self.obs['evidence_sha256'],reviewer=reviewer,action='BLOCK',decided_at=101)
  args.update(kwargs);return self.rbac.decide('e','r',**args)
 def test_first_review(self):self.assertFalse(self.decide()['review_complete'])
 def test_second_review(self):self.decide();self.assertTrue(self.decide('ops')['review_complete'])
 def test_no_execution(self):self.assertFalse(self.decide()['execution_authorized'])
 def test_no_cutover(self):self.assertFalse(self.decide()['cutover_authorized'])
 def test_no_retry(self):self.assertFalse(self.decide()['automatic_retry'])
 def test_disabled(self):
  with self.assertRaises(ReconciliationRBACError):self.decide('disabled')
 def test_unknown(self):
  with self.assertRaises(ReconciliationRBACError):self.decide('stranger')
 def test_duplicate(self):
  self.decide()
  with self.assertRaises(ReconciliationRBACError):self.decide()
 def test_same_role(self):
  self.rbac.set_reviewer('sec2','SECURITY',active=True);self.decide()
  with self.assertRaises(ReconciliationRBACError):self.decide('sec2')
 def test_conflicting(self):
  self.decide()
  with self.assertRaises(ReconciliationRBACError):self.decide('ops',action='ACKNOWLEDGE')
 def test_stale(self):
  self.rec.record('e','r',observed_at=101)
  with self.assertRaises(ReconciliationRBACError):self.decide(decided_at=102)
 def test_expired(self):
  with self.assertRaises(ReconciliationRBACError):self.decide(decided_at=5000)
 def test_changed_target(self):
  self.target.apply(event_id='e',owner='w',epoch=1,operation='READ_ONLY',permit_hash='p',request_id='r')
  with self.assertRaises(ReconciliationRBACError):self.decide()
 def test_tamper(self):
  self.decide();self.a.execute("UPDATE ldaps_rbac_decisions SET action='INVESTIGATE'")
  with self.assertRaises(ReconciliationRBACError):self.rbac.verify()
 def test_rollback(self):
  self.a.execute("CREATE TRIGGER deny_rbac BEFORE INSERT ON ldaps_rbac_decisions BEGIN SELECT RAISE(ABORT,'deny'); END")
  with self.assertRaises(sqlite3.IntegrityError):self.decide()
  self.assertEqual(self.rbac.verify()['count'],0)
if __name__=='__main__':unittest.main()
