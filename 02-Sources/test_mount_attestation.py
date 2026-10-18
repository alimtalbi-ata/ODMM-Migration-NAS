import unittest,tempfile
from mount_attestation import attest_mount,MountAttestationError,parse_mountinfo
class MountTests(unittest.TestCase):
 def test_nfs4(self):
  with tempfile.TemporaryDirectory() as d:
   s=f"25 1 0:44 / {d} rw,vers=4.1 - nfs nas:/vol rw"
   self.assertEqual(attest_mount(d,'NFSv4',mountinfo=s)['fstype'],'nfs')
 def test_smb(self):
  with tempfile.TemporaryDirectory() as d:
   self.assertEqual(attest_mount(d,'SMB',mountinfo=f"25 1 0:44 / {d} rw - cifs //nas/share rw")['fstype'],'cifs')
 def test_reject_wrong_type(self):
  with tempfile.TemporaryDirectory() as d:
   with self.assertRaises(MountAttestationError): attest_mount(d,'SMB',mountinfo=f"25 1 0:44 / {d} rw - ext4 /dev/sda rw")
 def test_reject_unverified_nfs3(self):
  with tempfile.TemporaryDirectory() as d:
   with self.assertRaises(MountAttestationError): attest_mount(d,'NFSv4',mountinfo=f"25 1 0:44 / {d} rw,vers=3 - nfs nas:/vol rw")
 def test_reject_nonmount(self):
  with tempfile.TemporaryDirectory() as d:
   with self.assertRaises(MountAttestationError): attest_mount(d,'SMB',mountinfo='')
 def test_mountinfo_escaped(self):
  self.assertEqual(parse_mountinfo('25 1 0:44 / /mnt/a\\040b rw - cifs //nas/share rw')[0]['mountpoint'],'/mnt/a b')
if __name__=='__main__': unittest.main()
