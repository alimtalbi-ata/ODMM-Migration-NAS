import copy
import os
import tempfile
import unittest
from pathlib import Path
from odmm_access_export_v2186 import create_checkpoint,verify_checkpoint,write_checkpoint,read_checkpoint
from odmm_access_anchor_v2185 import append_anchored
from odmm_access_audit_v2184 import AuditError,digest

class ExportTests(unittest.TestCase):
 def setUp(self):
  self.t=tempfile.TemporaryDirectory();self.addCleanup(self.t.cleanup)
  self.audit=Path(self.t.name)/'audit.sqlite';self.anchor=Path(self.t.name)/'anchor.sqlite'
  self.key=os.urandom(32)
  report={'cutover_authorized':False,'nas_qualified':False,'dedicated_account_attested':False}
  campaign={'report':report,'sha256':digest(report)}
  append_anchored(self.audit,self.anchor,campaign)
  self.checkpoint=create_checkpoint(self.audit,self.anchor,self.key,campaign_id='test')
 def test_roundtrip(self):
  p=Path(self.t.name)/'export.json';write_checkpoint(p,self.checkpoint)
  self.assertTrue(verify_checkpoint(read_checkpoint(p),self.key,audit_path=self.audit,anchor_path=self.anchor)['authenticated'])
 def test_tamper(self):
  bad=copy.deepcopy(self.checkpoint);bad['body']['entries']=99
  with self.assertRaisesRegex(AuditError,'AUTHENTICATION'):verify_checkpoint(bad,self.key)
 def test_wrong_key(self):
  with self.assertRaisesRegex(AuditError,'AUTHENTICATION'):verify_checkpoint(self.checkpoint,os.urandom(32))
 def test_weak_key(self):
  with self.assertRaisesRegex(AuditError,'WEAK'):create_checkpoint(self.audit,self.anchor,b'abc',campaign_id='x')
 def test_stale_checkpoint(self):
  report={'cutover_authorized':False,'nas_qualified':False,'dedicated_account_attested':False}
  append_anchored(self.audit,self.anchor,{'report':report,'sha256':digest(report)})
  with self.assertRaisesRegex(AuditError,'HEAD_MISMATCH'):verify_checkpoint(self.checkpoint,self.key,audit_path=self.audit,anchor_path=self.anchor)
 def test_no_overwrite(self):
  p=Path(self.t.name)/'export.json';write_checkpoint(p,self.checkpoint)
  with self.assertRaises(FileExistsError):write_checkpoint(p,self.checkpoint)
 def test_symlink_rejected(self):
  p=Path(self.t.name)/'export.json';p.symlink_to(self.audit)
  with self.assertRaises((FileExistsError,OSError)):write_checkpoint(p,self.checkpoint)
 def test_reject_forged_cutover(self):
  bad=copy.deepcopy(self.checkpoint);bad['body']['cutover_authorized']=True
  bad['hmac_sha256']=__import__('hmac').new(self.key,__import__('odmm_access_audit_v2184').canonical(bad['body']),__import__('hashlib').sha256).hexdigest()
  with self.assertRaisesRegex(AuditError,'UNTRUSTED'):verify_checkpoint(bad,self.key)
if __name__=='__main__':unittest.main()
