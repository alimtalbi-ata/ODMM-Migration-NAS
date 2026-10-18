import tempfile, unittest
from pathlib import Path
from path_preflight import preflight_path,PathPreflightError
from mount_attestation import parse_mountinfo
class PathTests(unittest.TestCase):
 def test_regular(self):
  with tempfile.TemporaryDirectory() as d:
   (Path(d)/'a').write_text('ok'); self.assertGreater(preflight_path(d,'a')['inode'],0)
 def test_nested(self):
  with tempfile.TemporaryDirectory() as d:
   (Path(d)/'folder').mkdir(); (Path(d)/'folder'/'x').write_text('ok'); preflight_path(d,'folder/x')
 def test_symlink(self):
  with tempfile.TemporaryDirectory() as d:
   (Path(d)/'x').write_text('ok'); (Path(d)/'link').symlink_to('x')
   with self.assertRaises(PathPreflightError): preflight_path(d,'link')
 def test_escape(self):
  with tempfile.TemporaryDirectory() as d:
   for p in ('../secret','/etc/passwd','./x'):
    with self.subTest(p=p),self.assertRaises(PathPreflightError): preflight_path(d,p)
 def test_mount_id(self):
  x=parse_mountinfo('43 20 0:40 / /mnt/nfs rw,relatime - nfs4 host:/vol rw,vers=4.1')
  self.assertEqual(x[0]['mount_id'],'43')
