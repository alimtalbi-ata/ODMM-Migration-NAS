import importlib.util, tempfile, pathlib, unittest, hashlib, json
BASE=pathlib.Path(__file__).parent
def load(name):
 spec=importlib.util.spec_from_file_location(name,BASE/(name+'.py'));m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m);return m
recover=load('RECOVER-WINDOWS-PUBLICATION').recover
validate=load('VALIDATE-WINDOWS-RELEASE').validate
def release(path,version='7.9.23'):
 path.mkdir(parents=True,exist_ok=True);items=[]
 for name in ['portable/ODMM-Compact.exe',f'installer/ODMM-Compact-Setup-V{version}.exe']:
  f=path/name;f.parent.mkdir();data=bytearray(1024);data[:2]=b'MZ';data[0x3c:0x40]=(128).to_bytes(4,'little');data[128:132]=b'PE\x00\x00';f.write_bytes(data)
  items.append({'file':name,'size':len(data),'sha256':hashlib.sha256(data).hexdigest()})
 (path/'SHA256-WINDOWS.json').write_text(json.dumps({'artifacts':items}))
 (path/'BUILD-STATUS.json').write_text(json.dumps({'version':version,'build':'completed','artifacts':items}))
class Tests(unittest.TestCase):
 def test_restore_valid_backup(self):
  with tempfile.TemporaryDirectory() as t:
   p=pathlib.Path(t)/'binary';release(pathlib.Path(t)/'binary.previous');self.assertIn('restored',recover(p));self.assertEqual(validate(p),'7.9.23')
 def test_refuse_corrupted_backup(self):
  with tempfile.TemporaryDirectory() as t:
   p=pathlib.Path(t)/'binary';backup=pathlib.Path(t)/'binary.previous';release(backup);(backup/'portable/ODMM-Compact.exe').write_bytes(b'bad')
   with self.assertRaises(ValueError):recover(p)
   self.assertFalse(p.exists());self.assertTrue(backup.exists())
 def test_preserve_valid_active(self):
  with tempfile.TemporaryDirectory() as t:
   p=pathlib.Path(t)/'binary';release(p);(pathlib.Path(t)/'binary.next').mkdir();recover(p);self.assertFalse((pathlib.Path(t)/'binary.next').exists())
 def test_refuse_corrupted_active(self):
  with tempfile.TemporaryDirectory() as t:
   p=pathlib.Path(t)/'binary';release(p);(p/'BUILD-STATUS.json').write_text('{}')
   with self.assertRaises(ValueError):recover(p)
 def test_orphan_candidate(self):
  with tempfile.TemporaryDirectory() as t:
   p=pathlib.Path(t)/'binary';(pathlib.Path(t)/'binary.next').mkdir()
   with self.assertRaises(RuntimeError):recover(p)
if __name__=='__main__':unittest.main()
