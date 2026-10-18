import os
import tempfile
import unittest
from pathlib import Path
from cryptography.exceptions import InvalidTag
from odmm_integrated_registry_v2030 import IntegratedRegistry
from odmm_registry_resilience_v2031 import export
from odmm_registry_secure_recovery_v2033 import encrypted_backup,encrypted_restore
class SecureRecoveryTests(unittest.TestCase):
 def setUp(self):
  self.t=tempfile.TemporaryDirectory();self.addCleanup(self.t.cleanup);self.d=Path(self.t.name);self.db=self.d/'registry.sqlite';IntegratedRegistry(self.db).create('campaign',['asset']);self.b=self.d/'backups';self.b.mkdir();self.key=os.urandom(32)
 def backup(self,name='odmm-01.aes',keep=5):return encrypted_backup(self.db,self.b,name=name,key=self.key,keep=keep)
 def test_roundtrip(self):
  r=self.backup();v=encrypted_restore(self.b/r['name'],self.d/'restored.sqlite',key=self.key,expected_sha256=r['ciphertext_sha256']);self.assertTrue(v['restored']);self.assertEqual(export(self.db),export(self.d/'restored.sqlite'))
 def test_no_plaintext(self):self.assertNotIn(b'SQLite format 3', (self.b/self.backup()['name']).read_bytes())
 def test_wrong_key(self):
  r=self.backup()
  with self.assertRaises(InvalidTag):encrypted_restore(self.b/r['name'],self.d/'restored.sqlite',key=os.urandom(32),expected_sha256=r['ciphertext_sha256'])
 def test_tamper(self):
  r=self.backup();p=self.b/r['name'];p.write_bytes(p.read_bytes()+b'x')
  with self.assertRaisesRegex(ValueError,'DIGEST_MISMATCH'):encrypted_restore(p,self.d/'restored.sqlite',key=self.key,expected_sha256=r['ciphertext_sha256'])
 def test_wrong_head(self):
  r=self.backup()
  with self.assertRaisesRegex(ValueError,'CHAIN_HEAD_MISMATCH'):encrypted_restore(self.b/r['name'],self.d/'restored.sqlite',key=self.key,expected_sha256=r['ciphertext_sha256'],expected_chain_head='f'*64)
 def test_no_overwrite(self):
  r=self.backup()
  with self.assertRaisesRegex(ValueError,'DESTINATION_EXISTS'):encrypted_restore(self.b/r['name'],self.db,key=self.key,expected_sha256=r['ciphertext_sha256'])
 def test_duplicate(self):
  self.backup()
  with self.assertRaisesRegex(ValueError,'DESTINATION_EXISTS'):self.backup()
 def test_rotation(self):
  for i in range(4):self.backup(f'odmm-{i}.aes',2)
  self.assertEqual(len(list(self.b.glob('odmm-*.aes'))),2)
 def test_invalid_key(self):
  with self.assertRaisesRegex(ValueError,'AES256_KEY_REQUIRED'):encrypted_backup(self.db,self.b,name='odmm-a.aes',key=b'bad')
 def test_invalid_name(self):
  with self.assertRaisesRegex(ValueError,'INVALID_NAME'):self.backup('../odmm-escape.aes')
 def test_no_nas_writes(self):
  nas=self.d/'nas';nas.write_bytes(b'unchanged');r=self.backup();encrypted_restore(self.b/r['name'],self.d/'restored.sqlite',key=self.key,expected_sha256=r['ciphertext_sha256']);self.assertEqual(nas.read_bytes(),b'unchanged')
if __name__=='__main__':unittest.main()
