import unittest,tempfile
from pathlib import Path
from fastapi import FastAPI
from fastapi.testclient import TestClient
from odmm_readonly_mount_probe_v2052 import probe,_mountinfo
from odmm_mount_cockpit_v2052 import PAGE,cockpit_csp,attach_mount_cockpit
M='31 1 0:44 / /mnt/odmm rw,relatime - nfs4 server:/export rw,vers=4.1\n32 1 0:45 / /mnt/odmm/sub ro,relatime - cifs //server/share ro,vers=3.1.1'
class TestMountV2052(unittest.TestCase):
 def test_longest_mount(self):self.assertEqual(_mountinfo('/mnt/odmm/sub/x',M)['filesystem'],'cifs')
 def test_nfs(self):
  with tempfile.TemporaryDirectory() as d:
   m=f'31 1 0:44 / {d} ro,relatime - nfs4 server:/export rw,vers=4.1'
   x=probe(d,mountinfo=m);self.assertEqual(x['protocol_family'],'NFS');self.assertFalse(x['cutover_authorized']);self.assertEqual(x['acl'],'UNVERIFIED')
 def test_smb(self):
  with tempfile.TemporaryDirectory() as d:
   m=f'31 1 0:44 / {d} rw - cifs //host/share rw,vers=3.1.1'
   self.assertEqual(probe(d,mountinfo=m)['protocol_family'],'SMB')
 def test_local_rejected(self):
  with tempfile.TemporaryDirectory() as d:
   with self.assertRaises(ValueError):probe(d,mountinfo=f'31 1 0:44 / {d} rw - ext4 /dev/sda rw')
 def test_symlink_rejected(self):
  with tempfile.TemporaryDirectory() as d:
   p=Path(d)/'link';p.symlink_to(d)
   with self.assertRaises(ValueError):probe(p,mountinfo='')
 def test_ui(self):
  for s in ('mount-file','mount-rows','UNVERIFIED','Cutover interdit'):self.assertIn(s,PAGE)
 def test_no_fetch(self):self.assertNotIn('fetch(',PAGE)
 def test_csp(self):self.assertGreaterEqual(cockpit_csp().count("'sha256-"),6)
 def test_auth_required(self):
  with self.assertRaises(ValueError):attach_mount_cockpit(FastAPI(),authorize=None)
 def test_auth_denied(self):
  app=FastAPI();attach_mount_cockpit(app,authorize=lambda r:False)
  self.assertEqual(TestClient(app).get('/qualification/cockpit').status_code,403)
 def test_auth_allowed(self):
  app=FastAPI();attach_mount_cockpit(app,authorize=lambda r:True)
  self.assertEqual(TestClient(app).get('/qualification/cockpit').status_code,200)
if __name__=='__main__':unittest.main()
