import tempfile
import unittest
from pathlib import Path
from odmm_native_ownership_v2122 import OwnershipRegistry
from odmm_native_secure_v2120 import SecureStaging, Blocked
from odmm_native_owned_stage_v2123 import OwnedStaging

class TestOwnedStage(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory(); root=Path(self.tmp.name)
        self.src=root/'src'; self.dst=root/'dst'; self.src.mkdir(); self.dst.mkdir()
        self.now=[1_000_000_000_000]
        self.reg=OwnershipRegistry(root/'ownership.db',clock=lambda:self.now[0])
        self.staging=SecureStaging(self.src,self.dst,root/'transfers.db')
        self.claim=self.reg.claim('target:share','worker-a',ttl_ns=100_000_000)
        self.owned=OwnedStaging(self.staging,self.reg,self.claim)
    def tearDown(self):
        self.staging.close(); self.reg.close(); self.tmp.cleanup()
    def test_publish_and_evidence(self):
        (self.src/'a').write_bytes(b'abc'); result=self.owned.stage('a')
        self.assertEqual((self.dst/'a').read_bytes(),b'abc')
        self.assertEqual(result.epoch,1); self.assertFalse(result.cutover_authorized)
    def test_stale_after_expiry(self):
        self.now[0]+=100_000_001
        (self.src/'a').write_bytes(b'abc')
        with self.assertRaises(Blocked): self.owned.stage('a')
        self.assertFalse((self.dst/'a').exists())
    def test_stale_after_new_owner(self):
        self.now[0]+=100_000_001
        self.reg.claim('target:share','worker-b',ttl_ns=100_000_000)
        with self.assertRaises(Blocked): self.owned.pending()
    def test_renew_invalidates_old_claim(self):
        self.now[0]+=1_000_000
        self.reg.renew(self.claim,ttl_ns=200_000_000)
        with self.assertRaises(Blocked): self.owned.stage('x')
    def test_release_blocks(self):
        self.reg.release(self.claim)
        with self.assertRaises(Blocked): self.owned.pending()
    def test_existing_target_preserved(self):
        (self.src/'a').write_bytes(b'new'); (self.dst/'a').write_bytes(b'old')
        with self.assertRaises(Blocked): self.owned.stage('a')
        self.assertEqual((self.dst/'a').read_bytes(),b'old')
    def test_no_path_traversal(self):
        with self.assertRaises(Blocked): self.owned.stage('../x')
    def test_pending_read(self):
        self.assertEqual(self.owned.pending(),[])
    def test_fence_exception_closed(self):
        class Bad:
            def verify(self,claim): raise RuntimeError('offline')
        with self.assertRaises(Blocked): OwnedStaging(self.staging,Bad(),self.claim).stage('x')

if __name__=='__main__': unittest.main()
