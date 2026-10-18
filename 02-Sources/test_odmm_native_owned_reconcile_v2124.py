"""V212.4 local POSIX ownership reconciliation tests."""
import tempfile
import unittest
from pathlib import Path
from odmm_native_ownership_v2122 import OwnershipRegistry
from odmm_native_reconcile_v2121 import ReconciledStaging
from odmm_native_owned_reconcile_v2124 import OwnedReconciler
from odmm_native_secure_v2120 import Blocked

class Tests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory()
        root=Path(self.temp.name)
        self.src=root/'src'; self.dst=root/'dst'; self.src.mkdir(); self.dst.mkdir()
        self.clock=[1_000_000_000_000]
        self.registry=OwnershipRegistry(root/'owner.db',clock=lambda:self.clock[0])
        self.claim=self.registry.claim('nas:pilot','worker-1',ttl_ns=10_000_000_000)
        self.staging=ReconciledStaging(self.src,self.dst,root/'journal.db')
        self.subject=OwnedReconciler(self.staging,self.registry,self.claim)
    def tearDown(self):
        self.staging.close(); self.registry.close(); self.temp.cleanup()
    def test_empty_is_not_clean(self):
        e=self.subject.reconcile(); self.assertFalse(e.clean); self.assertFalse(e.cutover_authorized)
    def test_verified_target_clean_but_not_cutover(self):
        (self.src/'a').write_bytes(b'hello')
        self.staging.stage('a',fence=lambda:self.registry.verify(self.claim))
        e=self.subject.reconcile(); self.assertTrue(e.clean); self.assertFalse(e.acl_fidelity_verified)
        self.assertEqual(e.entries[0]['target_status'],'MATCH')
    def test_corrupt_target_requires_review(self):
        (self.src/'a').write_bytes(b'hello'); self.staging.stage('a',fence=lambda:True)
        (self.dst/'a').write_bytes(b'changed')
        e=self.subject.reconcile(); self.assertFalse(e.clean); self.assertTrue(e.entries[0]['requires_human_review'])
    def test_expired_claim_denied(self):
        self.clock[0]+=11_000_000_000
        with self.assertRaises(Blocked): self.subject.reconcile()
    def test_replaced_claim_denied(self):
        self.clock[0]+=11_000_000_000
        self.registry.claim('nas:pilot','worker-2',ttl_ns=10_000_000_000)
        with self.assertRaises(Blocked): self.subject.reconcile()
    def test_renewal_invalidates_old_claim(self):
        self.registry.renew(self.claim,ttl_ns=20_000_000_000)
        with self.assertRaises(Blocked): self.subject.reconcile()
    def test_strict_true_only(self):
        class BadRegistry:
            def verify(self, claim): return 1
        with self.assertRaises(Blocked): OwnedReconciler(self.staging,BadRegistry(),self.claim).reconcile()
    def test_provider_exception_denied(self):
        class BadRegistry:
            def verify(self, claim): raise OSError('offline')
        with self.assertRaises(Blocked): OwnedReconciler(self.staging,BadRegistry(),self.claim).reconcile()
    def test_invalid_constructor(self):
        with self.assertRaises(Blocked): OwnedReconciler(object(),self.registry,self.claim)

if __name__=='__main__': unittest.main()
