import copy
import tempfile
import unittest
from pathlib import Path
from directory_snapshot_adapter import DirectorySnapshotPolicyLedger
from directory_freshness_gate import assess_directory_freshness,verify_directory_freshness
from human_approval_registry import ApprovalError

BASE={'source':'AD_EXPORT','version':'v1','accounts':[
 {'id':'alice','enabled':True,'groups':['ODMM_SECURITY_REVIEWERS']},
 {'id':'bob','enabled':True,'groups':['ODMM_OPERATIONS_REVIEWERS']}]}

class FreshnessTests(unittest.TestCase):
 def setUp(self):
  self.temp=tempfile.TemporaryDirectory()
  self.ledger=DirectorySnapshotPolicyLedger(str(Path(self.temp.name)/'db.sqlite'),issuer_secret=b'x'*32)
  self.digest=self.ledger.apply_export(BASE)['sha256']
 def tearDown(self):
  self.ledger.db.close();self.temp.cleanup()
 def check(self,export=None,**kwargs):
  return assess_directory_freshness(self.ledger,export if export is not None else BASE,
    expected_digest=kwargs.pop('expected_digest',self.digest),observed_at=kwargs.pop('observed_at',100),
    now=kwargs.pop('now',110),max_age_seconds=kwargs.pop('max_age_seconds',900),**kwargs)
 def test_consistent(self):
  b=self.check();self.assertEqual(b['report']['status'],'OFFLINE_SNAPSHOT_CONSISTENT_NOT_AUTHENTICATED');self.assertFalse(b['report']['cutover_authorized'])
 def test_deterministic(self):self.assertEqual(self.check(),self.check())
 def test_expired(self):self.assertIn('SNAPSHOT_EXPIRED',self.check(now=2000)['report']['reasons'])
 def test_future(self):self.assertIn('FUTURE_OBSERVATION',self.check(now=90)['report']['reasons'])
 def test_changed_role(self):
  b=copy.deepcopy(BASE);b['accounts'][0]['groups']=[]
  r=self.check(b)['report'];self.assertIn('REVIEWER_MEMBERSHIP_DRIFT',r['reasons'])
 def test_disabled(self):
  b=copy.deepcopy(BASE);b['accounts'][0]['enabled']=False
  self.assertEqual(self.check(b)['report']['reviewer_changes'][0]['reviewer'],'alice')
 def test_omitted(self):
  b=copy.deepcopy(BASE);b['accounts']=b['accounts'][1:]
  self.assertIn('REVIEWER_MEMBERSHIP_DRIFT',self.check(b)['report']['reasons'])
 def test_added(self):
  b=copy.deepcopy(BASE);b['accounts'].append({'id':'charlie','enabled':True,'groups':['ODMM_SECURITY_REVIEWERS']})
  self.assertEqual(len(self.check(b)['report']['reviewer_changes']),1)
 def test_wrong_expected_digest(self):
  self.assertIn('SNAPSHOT_DIGEST_MISMATCH',self.check(expected_digest='0'*64)['report']['reasons'])
 def test_bad_digest(self):
  with self.assertRaises(ApprovalError):self.check(expected_digest='invalid')
 def test_invalid_time(self):
  with self.assertRaises(ApprovalError):self.check(now=True)
 def test_tamper(self):
  b=self.check();b['report']['status']='OK'
  with self.assertRaises(ApprovalError):verify_directory_freshness(self.ledger,BASE,b,expected_digest=self.digest,observed_at=100,now=110)
 def test_no_snapshot(self):
  self.ledger.db.execute('DELETE FROM directory_sync_state')
  self.assertIn('NO_APPLIED_SNAPSHOT',self.check()['report']['reasons'])
 def test_readonly(self):
  before=self.ledger.db.total_changes;self.check();self.assertEqual(self.ledger.db.total_changes,before)
