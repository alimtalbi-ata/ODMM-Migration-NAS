import tempfile
import unittest
from pathlib import Path
from odmm_native_ownership_v2122 import OwnershipRegistry,OwnershipBlocked

class OwnershipTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory()
        self.now=[1_000_000_000_000]
        self.path=Path(self.tmp.name)/'owner.db'
        self.a=OwnershipRegistry(self.path,clock=lambda:self.now[0])
        self.b=OwnershipRegistry(self.path,clock=lambda:self.now[0])
    def tearDown(self):
        self.a.close();self.b.close();self.tmp.cleanup()
    def test_claim_and_verify(self):
        c=self.a.claim('nas:vol','worker1',ttl_ns=10_000_000)
        self.assertTrue(self.b.verify(c))
    def test_duplicate_blocked(self):
        self.a.claim('nas:vol','worker1',ttl_ns=10_000_000)
        with self.assertRaises(OwnershipBlocked):self.b.claim('nas:vol','worker2',ttl_ns=10_000_000)
    def test_expiry_and_epoch(self):
        c=self.a.claim('nas:vol','worker1',ttl_ns=10_000_000)
        self.now[0]+=11_000_000
        n=self.b.claim('nas:vol','worker2',ttl_ns=10_000_000)
        self.assertEqual(n.epoch,c.epoch+1)
        self.assertFalse(self.a.verify(c))
        with self.assertRaises(OwnershipBlocked):self.a.release(c)
    def test_renew_cas(self):
        c=self.a.claim('nas:vol','worker1',ttl_ns=10_000_000)
        self.now[0]+=1_000_000
        n=self.b.renew(c,ttl_ns=20_000_000)
        self.assertTrue(self.a.verify(n))
        self.assertFalse(self.a.verify(c))
        with self.assertRaises(OwnershipBlocked):self.a.renew(c,ttl_ns=20_000_000)
    def test_release(self):
        c=self.a.claim('nas:vol','worker1',ttl_ns=10_000_000)
        self.a.release(c)
        self.assertFalse(self.a.verify(c))
        self.assertEqual(self.b.claim('nas:vol','worker2',ttl_ns=10_000_000).epoch,2)
    def test_invalid_ttl(self):
        with self.assertRaises(OwnershipBlocked):self.a.claim('x','y',ttl_ns=True)
    def test_invalid_identity(self):
        with self.assertRaises(OwnershipBlocked):self.a.claim('../x\n','y',ttl_ns=10_000_000)
    def test_export(self):
        self.a.claim('nas:vol','worker1',ttl_ns=10_000_000)
        x=self.a.audit_export()
        self.assertEqual(len(x['events']),1)
        self.assertFalse(x['tamper_evident'])
        self.assertFalse(x['cutover_authorized'])
    def test_expired_renew_fails(self):
        c=self.a.claim('nas:vol','worker1',ttl_ns=10_000_000)
        self.now[0]+=11_000_000
        with self.assertRaises(OwnershipBlocked):self.a.renew(c,ttl_ns=20_000_000)

if __name__=='__main__':unittest.main()
