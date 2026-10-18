import unittest, tempfile, pathlib
from types import SimpleNamespace
from mounted_acl_collector import collect_mounted_acl, CollectionError
from collector_provenance import sign_capture, ProvenanceRegistry, EvidenceRejected
import time
class MountedCollectorTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory(); self.root=pathlib.Path(self.tmp.name); (self.root/'file').write_bytes(b'data')
    def tearDown(self): self.tmp.cleanup()
    def collect(self,protocol='NFSv4',path='file',runner=None):
        return collect_mounted_acl(self.root,path,protocol,'source','collector-a','test-domain',runner=runner or (lambda argv:SimpleNamespace(returncode=0,stdout=b'ACL:example',stderr=b'')))
    def test_nfs_capture(self):
        r=self.collect(); self.assertEqual(r['tool'],'nfs4_getfacl'); self.assertTrue(r['capture']['complete'])
    def test_smb_capture(self): self.assertEqual(self.collect('SMB')['tool'],'getcifsacl')
    def test_reject_traversal(self):
        with self.assertRaises(CollectionError): self.collect(path='../file')
    def test_reject_symlink(self):
        (self.root/'link').symlink_to(self.root/'file')
        with self.assertRaises(CollectionError): self.collect(path='link')
    def test_reject_failed_tool(self):
        with self.assertRaises(CollectionError): self.collect(runner=lambda argv:SimpleNamespace(returncode=1,stdout=b'',stderr=b'fail'))
    def test_reject_empty(self):
        with self.assertRaises(CollectionError): self.collect(runner=lambda argv:SimpleNamespace(returncode=0,stdout=b'',stderr=b''))
    def test_sign_and_replay_reject(self):
        capture=self.collect()['capture']; key=b'k'*32
        envelope=sign_capture(capture,'collector-a','unique-nonce-123456789',int(time.time()),key)
        db=self.root/'provenance.sqlite'; reg=ProvenanceRegistry(str(db),{'collector-a':key})
        try:
            self.assertEqual(reg.verify_and_record(envelope)['status'],'AUTHENTICATED_ENVELOPE_ONLY')
            with self.assertRaises(EvidenceRejected): reg.verify_and_record(envelope)
        finally: reg.close()
if __name__=='__main__': unittest.main()
