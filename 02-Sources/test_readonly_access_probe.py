import os, tempfile, unittest
from pathlib import Path
from readonly_access_probe import probe_readonly, AccessProbeError

class ReadonlyProbeTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory(); self.root=Path(self.tmp.name); (self.root/'file').write_text('data')
    def tearDown(self): self.tmp.cleanup()
    def test_success_without_reading(self):
        result=probe_readonly(self.root,'file',expected_euid=os.geteuid())
        self.assertEqual(result['report']['outcome'],'OPEN_READ_SUCCEEDED')
        self.assertFalse(result['report']['production_qualified'])
    def test_stable_hash(self):
        a=probe_readonly(self.root,'file',expected_euid=os.geteuid())
        b=probe_readonly(self.root,'file',expected_euid=os.geteuid())
        self.assertEqual(a,b)
    def test_identity_mismatch(self):
        with self.assertRaises(AccessProbeError): probe_readonly(self.root,'file',expected_euid=os.geteuid()+1)
    def test_group_mismatch(self):
        with self.assertRaises(AccessProbeError): probe_readonly(self.root,'file',expected_euid=os.geteuid(),expected_egid=os.getegid()+1)
    def test_symlink_rejected(self):
        (self.root/'link').symlink_to('file')
        with self.assertRaises(AccessProbeError): probe_readonly(self.root,'link',expected_euid=os.geteuid())
    def test_directory_rejected(self):
        with self.assertRaises(AccessProbeError): probe_readonly(self.root,'.',expected_euid=os.geteuid())
    def test_traversal_rejected(self):
        with self.assertRaises(AccessProbeError): probe_readonly(self.root,'../file',expected_euid=os.geteuid())
    def test_no_write(self):
        before=(self.root/'file').read_bytes()
        probe_readonly(self.root,'file',expected_euid=os.geteuid())
        self.assertEqual(before,(self.root/'file').read_bytes())

if __name__=='__main__': unittest.main()
