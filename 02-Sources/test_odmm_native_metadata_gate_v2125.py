import os
import tempfile
import unittest
from pathlib import Path
from odmm_native_secure_v2120 import SecureStaging, Blocked
from odmm_native_ownership_v2122 import OwnershipRegistry
from odmm_native_owned_stage_v2123 import OwnedStaging
from odmm_native_metadata_gate_v2125 import MetadataGatedStaging

class TestMetadataGate(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory(); root=Path(self.tmp.name)
        self.src=root/'src'; self.dst=root/'dst'; self.src.mkdir(); self.dst.mkdir()
        self.reg=OwnershipRegistry(root/'ownership.db')
        self.staging=SecureStaging(self.src,self.dst,root/'journal.db')
        self.claim=self.reg.claim('test','worker',ttl_ns=10_000_000_000)
        self.gate=MetadataGatedStaging(OwnedStaging(self.staging,self.reg,self.claim))
    def tearDown(self):
        self.staging.close(); self.reg.close(); self.tmp.cleanup()
    def source(self,name='file',mode=0o600):
        p=self.src/name; p.write_bytes(b'hello'); p.chmod(mode); return p
    def test_safe_local_pilot(self):
        self.source(); result=self.gate.stage('file')
        self.assertEqual((self.dst/'file').read_bytes(),b'hello')
        self.assertFalse(result['acl_fidelity_verified'])
        self.assertTrue(result['requires_human_review'])
    def test_reject_nontrivial_mode(self):
        self.source(mode=0o640)
        with self.assertRaisesRegex(Blocked,'UNSUPPORTED_MODE'): self.gate.stage('file')
        self.assertFalse((self.dst/'file').exists())
    def test_reject_symlink(self):
        self.source('original'); (self.src/'file').symlink_to('original')
        with self.assertRaises(OSError): self.gate.stage('file')
        self.assertFalse((self.dst/'file').exists())
    def test_reject_traversal(self):
        with self.assertRaises(Blocked): self.gate.inspect('../file')
    def test_reject_expired_claim(self):
        self.source(); self.reg.release(self.claim)
        with self.assertRaisesRegex(Blocked,'STALE_OWNER'): self.gate.stage('file')
    def test_reject_xattrs_when_supported(self):
        p=self.source()
        try: os.setxattr(p,'user.odmm_test',b'1')
        except (AttributeError,OSError): self.skipTest('xattrs unavailable')
        with self.assertRaisesRegex(Blocked,'UNSUPPORTED_XATTR_OR_ACL'): self.gate.stage('file')
        self.assertFalse((self.dst/'file').exists())
    def test_reject_hardlink(self):
        p=self.source(); os.link(p,self.src/'other')
        with self.assertRaisesRegex(Blocked,'UNSAFE_SOURCE_TYPE'): self.gate.stage('file')
    def test_no_overwrite(self):
        self.source(); (self.dst/'file').write_bytes(b'existing')
        with self.assertRaises(Blocked): self.gate.stage('file')
        self.assertEqual((self.dst/'file').read_bytes(),b'existing')

if __name__=='__main__': unittest.main()
