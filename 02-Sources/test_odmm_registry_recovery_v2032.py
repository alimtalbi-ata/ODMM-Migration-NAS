import os
import tempfile
import unittest
from pathlib import Path
from odmm_integrated_registry_v2030 import IntegratedRegistry
from odmm_registry_recovery_v2032 import backup,restore
from odmm_registry_resilience_v2031 import export
class RecoveryTests(unittest.TestCase):
 def setUp(self):
  self.t=tempfile.TemporaryDirectory();self.addCleanup(self.t.cleanup)
  self.p=Path(self.t.name);self.db=self.p/'registry.db';IntegratedRegistry(self.db).create('camp',['asset'])
  self.b=self.p/'backups';self.b.mkdir()
 def save(self,n='odmm-01.sqlite',keep=5):return backup(self.db,self.b,name=n,keep=keep)
 def test_backup(self):self.assertEqual(self.save()['chain_head'],'0'*64)
 def test_restore(self):
  x=self.save();r=restore(self.b/x['backup_name'],self.p/'restored.sqlite',expected_sha256=x['backup_sha256'],expected_chain_head=x['chain_head']);self.assertTrue(r['restored']);self.assertEqual(export(self.db),export(self.p/'restored.sqlite'))
 def test_restore_no_overwrite(self):
  x=self.save()
  with self.assertRaisesRegex(ValueError,'DESTINATION_EXISTS'):restore(self.b/x['backup_name'],self.db,expected_sha256=x['backup_sha256'])
 def test_tamper(self):
  x=self.save();(self.b/x['backup_name']).write_bytes(b'corrupt')
  with self.assertRaisesRegex(ValueError,'DIGEST_MISMATCH'):restore(self.b/x['backup_name'],self.p/'new.sqlite',expected_sha256=x['backup_sha256'])
 def test_bad_head(self):
  x=self.save()
  with self.assertRaisesRegex(ValueError,'CHAIN_HEAD_MISMATCH'):restore(self.b/x['backup_name'],self.p/'new.sqlite',expected_sha256=x['backup_sha256'],expected_chain_head='a'*64)
 def test_duplicate(self):
  self.save()
  with self.assertRaisesRegex(ValueError,'BACKUP_EXISTS'):self.save()
 def test_retention(self):
  for n in range(4):self.save(f'odmm-{n:02d}.sqlite',keep=2)
  self.assertEqual(len(list(self.b.glob('odmm-*.sqlite'))),2)
 def test_symlink(self):
  (self.b/'odmm-link.sqlite').symlink_to(self.db)
  with self.assertRaisesRegex(ValueError,'BACKUP_EXISTS'):self.save('odmm-link.sqlite')
 def test_invalid_name(self):
  with self.assertRaisesRegex(ValueError,'INVALID_BACKUP_NAME'):self.save('../odmm-escape.sqlite')
 def test_invalid_keep(self):
  with self.assertRaisesRegex(ValueError,'INVALID_RETENTION'):backup(self.db,self.b,name='odmm-01.sqlite',keep=0)
 def test_missing_registry(self):
  with self.assertRaisesRegex(ValueError,'REGISTRY_MISSING'):backup(self.p/'missing',self.b,name='odmm-01.sqlite')
 def test_unrelated_untouched(self):
  other=self.b/'keep.txt';other.write_text('safe')
  for n in range(3):self.save(f'odmm-{n}.sqlite',keep=1)
  self.assertEqual(other.read_text(),'safe')
 def test_no_nas_write(self):
  source=self.p/'nas_fixture';source.write_bytes(b'untouched');x=self.save();restore(self.b/x['backup_name'],self.p/'new.sqlite',expected_sha256=x['backup_sha256']);self.assertEqual(source.read_bytes(),b'untouched')
if __name__=='__main__':unittest.main()
