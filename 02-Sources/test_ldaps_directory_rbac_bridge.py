import sqlite3, unittest
from ldaps_crash_reconciliation import CrashReconciliationLedger
from ldaps_durable_target import DurableFencedTarget
from ldaps_rbac_reconciliation import ReconciliationRBAC,ReconciliationRBACError
from ldaps_directory_rbac_bridge import DirectoryRBACBridge
class C:
 def __init__(self,db):self.db=db
class Tests(unittest.TestCase):
 def setUp(self):
  self.a=sqlite3.connect(':memory:',isolation_level=None);self.b=sqlite3.connect(':memory:',isolation_level=None)
  self.target=DurableFencedTarget(self.b);self.target.advance_epoch('e',1)
  self.rec=CrashReconciliationLedger(C(self.a),self.target)
  self.rbac=ReconciliationRBAC(self.rec);self.bridge=DirectoryRBACBridge(self.rbac)
  self.obs=self.rec.record('e','r',observed_at=100)
 def tearDown(self):self.a.close();self.b.close()
 def exp(self,version='v1',sec=True,ops=True):
  return {'source':'LDAP_EXPORT','version':version,'accounts':[{'id':'sec','enabled':sec,'groups':['ODMM_SECURITY_REVIEWERS']},{'id':'ops','enabled':ops,'groups':['ODMM_OPERATIONS_REVIEWERS']}]}
 def apply(self,export=None,**kw):return self.bridge.apply(export or self.exp(),now=101,**kw)
 def decide(self,who):return self.rbac.decide('e','r',observation_hash=self.obs['evidence_sha256'],reviewer=who,action='BLOCK',decided_at=102)
 def test_grants(self):self.assertEqual(self.apply()['changed_reviewers'],['ops','sec'])
 def test_security_review(self):self.apply();self.assertFalse(self.decide('sec')['review_complete'])
 def test_dual_review(self):self.apply();self.decide('sec');self.assertTrue(self.decide('ops')['review_complete'])
 def test_disabled_rejected(self):
  self.apply(self.exp(sec=False))
  with self.assertRaises(ReconciliationRBACError):self.decide('sec')
 def test_missing_revoked(self):
  first=self.apply();self.apply({'source':'LDAP_EXPORT','version':'v2','accounts':[{'id':'ops','enabled':True,'groups':['ODMM_OPERATIONS_REVIEWERS']}]},expected_previous_digest=first['snapshot_sha256'])
  with self.assertRaises(ReconciliationRBACError):self.decide('sec')
 def test_review_invalidated(self):
  first=self.apply();self.decide('sec');result=self.apply(self.exp('v2',sec=False),expected_previous_digest=first['snapshot_sha256'])
  self.assertEqual(result['review_invalidations'],1)
  with self.assertRaisesRegex(ReconciliationRBACError,'REVIEW_INVALIDATED'):self.decide('ops')
 def test_unchanged_review_remains(self):
  first=self.apply();self.decide('sec');self.apply(self.exp('v2'),expected_previous_digest=first['snapshot_sha256']);self.assertTrue(self.decide('ops')['review_complete'])
 def test_conflict(self):
  self.apply()
  with self.assertRaisesRegex(ReconciliationRBACError,'CONFLICT'):self.apply(self.exp('v2'))
 def test_version_reuse(self):
  first=self.apply()
  with self.assertRaisesRegex(ReconciliationRBACError,'VERSION_REUSED'):self.apply(self.exp(sec=False),expected_previous_digest=first['snapshot_sha256'])
 def test_tamper(self):
  self.apply();self.a.execute("UPDATE ldaps_rbac_grant_audit SET changed='bad'")
  with self.assertRaisesRegex(ReconciliationRBACError,'TAMPERED'):self.bridge.verify()
 def test_fail_closed_decision_on_tamper(self):
  self.apply();self.a.execute("UPDATE ldaps_rbac_grant_audit SET changed='bad'")
  with self.assertRaisesRegex(ReconciliationRBACError,'TAMPERED'):self.decide('sec')
 def test_rollback(self):
  self.a.execute("CREATE TRIGGER deny_grant BEFORE INSERT ON ldaps_rbac_grant_audit BEGIN SELECT RAISE(ABORT,'deny'); END")
  with self.assertRaises(sqlite3.IntegrityError):self.apply()
  self.assertEqual(self.a.execute('SELECT COUNT(*) FROM ldaps_rbac_users').fetchone()[0],0)
 def test_no_authorization(self):
  x=self.apply();self.assertFalse(x['execution_authorized']);self.assertFalse(x['cutover_authorized']);self.assertFalse(x['authenticated'])
 def test_invalid_timestamp(self):
  with self.assertRaises(ReconciliationRBACError):self.bridge.apply(self.exp(),now=True)
 def test_audit(self):self.apply();self.assertEqual(self.bridge.verify()['count'],1)
if __name__=='__main__':unittest.main()
