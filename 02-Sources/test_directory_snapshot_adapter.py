import copy
import tempfile
import unittest
from pathlib import Path
from human_approval_registry import ApprovalError
from directory_snapshot_adapter import normalize_directory_export,DirectorySnapshotPolicyLedger

BASE={'source':'AD_EXPORT','version':'v1','accounts':[
 {'id':'alice','enabled':True,'groups':['ODMM_SECURITY_REVIEWERS']},
 {'id':'bob','enabled':True,'groups':['ODMM_OPERATIONS_REVIEWERS']}]}
class DirectorySnapshotTests(unittest.TestCase):
 def test_normalization_deterministic(self):
  a=normalize_directory_export(BASE); b=copy.deepcopy(BASE); b['accounts'].reverse()
  self.assertEqual(a,normalize_directory_export(b)); self.assertFalse(a['authenticated'])
 def test_invalid_source(self):
  b=copy.deepcopy(BASE); b['source']='LIVE_AD'
  with self.assertRaises(ApprovalError):normalize_directory_export(b)
 def test_duplicate_account(self):
  b=copy.deepcopy(BASE);b['accounts'].append(copy.deepcopy(b['accounts'][0]))
  with self.assertRaises(ApprovalError):normalize_directory_export(b)
 def test_conflicting_roles(self):
  b=copy.deepcopy(BASE);b['accounts'][0]['groups'].append('ODMM_OPERATIONS_REVIEWERS')
  with self.assertRaises(ApprovalError):normalize_directory_export(b)
 def test_unknown_group(self):
  b=copy.deepcopy(BASE);b['accounts'][0]['groups']=['Domain Admins']
  with self.assertRaises(ApprovalError):normalize_directory_export(b)
 def test_disabled(self):
  b=copy.deepcopy(BASE);b['accounts'][0]['enabled']=False
  self.assertFalse(normalize_directory_export(b)['normalized']['accounts'][0]['active'])
 def test_empty_export(self):
  b=copy.deepcopy(BASE);b['accounts']=[]
  with self.assertRaises(ApprovalError):normalize_directory_export(b)
 def test_sync_and_omitted_disabled(self):
  with tempfile.TemporaryDirectory() as d:
   db=DirectorySnapshotPolicyLedger(str(Path(d)/'test.db'),issuer_secret=b'x'*32)
   first=db.apply_export(BASE)
   self.assertFalse(first['cutover_authorized'])
   self.assertEqual(db.db.execute("SELECT active FROM reviewer_directory WHERE reviewer='alice'").fetchone()[0],1)
   b=copy.deepcopy(BASE);b['version']='v2';b['accounts']=b['accounts'][1:]
   db.apply_export(b,expected_previous_digest=first['sha256'])
   self.assertEqual(db.db.execute("SELECT active FROM reviewer_directory WHERE reviewer='alice'").fetchone()[0],0)
   db.db.close()
 def test_cas_conflict_preserves_state(self):
  with tempfile.TemporaryDirectory() as d:
   db=DirectorySnapshotPolicyLedger(str(Path(d)/'test.db'),issuer_secret=b'x'*32)
   first=db.apply_export(BASE);b=copy.deepcopy(BASE);b['version']='v2'
   with self.assertRaises(ApprovalError):db.apply_export(b,expected_previous_digest='0'*64)
   self.assertEqual(db.db.execute('SELECT digest FROM directory_sync_state').fetchone()[0],first['sha256'])
   db.db.close()
 def test_version_reuse_rejected(self):
  with tempfile.TemporaryDirectory() as d:
   db=DirectorySnapshotPolicyLedger(str(Path(d)/'test.db'),issuer_secret=b'x'*32)
   first=db.apply_export(BASE);b=copy.deepcopy(BASE);b['accounts'][0]['enabled']=False
   with self.assertRaises(ApprovalError):db.apply_export(b,expected_previous_digest=first['sha256'])
   db.db.close()
 def test_missing_fields(self):
  b=copy.deepcopy(BASE);del b['accounts'][0]['enabled']
  with self.assertRaises(ApprovalError):normalize_directory_export(b)
 def test_invalid_version(self):
  b=copy.deepcopy(BASE);b['version']='../unsafe'
  with self.assertRaises(ApprovalError):normalize_directory_export(b)
