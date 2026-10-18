import tempfile
import unittest
from pathlib import Path
from odmm_native_reconcile_v2121 import ReconciledStaging, Blocked

class ReconcileTests(unittest.TestCase):
    def setUp(self):
        self.t=tempfile.TemporaryDirectory(); p=Path(self.t.name)
        self.src=p/'src'; self.dst=p/'dst'; self.src.mkdir(); self.dst.mkdir()
        (self.src/'a').write_bytes(b'original')
        self.s=ReconciledStaging(self.src,self.dst,p/'journal.db')
    def tearDown(self): self.s.close(); self.t.cleanup()
    def test_verified_match(self):
        self.s.stage('a',fence=lambda:True)
        x=self.s.reconcile(fence=lambda:True)[0]
        self.assertEqual((x['journal_state'],x['target_status']),('VERIFIED','MATCH'))
        self.assertFalse(x['cutover_authorized'])
        self.assertFalse(x['requires_human_review'])
    def test_tamper(self):
        self.s.stage('a',fence=lambda:True)
        (self.dst/'a').write_bytes(b'tampered')
        self.assertEqual(self.s.reconcile(fence=lambda:True)[0]['target_status'],'HASH_MISMATCH')
    def test_missing(self):
        self.s.stage('a',fence=lambda:True); (self.dst/'a').unlink()
        self.assertEqual(self.s.reconcile(fence=lambda:True)[0]['target_status'],'MISSING')
    def test_pending(self):
        calls=iter([True,False])
        with self.assertRaises(Blocked): self.s.stage('a',fence=lambda:next(calls))
        x=self.s.reconcile(fence=lambda:True)[0]
        self.assertEqual(x['journal_state'],'PENDING')
        self.assertTrue(x['requires_human_review'])
    def test_symlink_target(self):
        self.s.stage('a',fence=lambda:True); (self.dst/'a').unlink()
        (self.dst/'a').symlink_to(self.src/'a')
        self.assertEqual(self.s.reconcile(fence=lambda:True)[0]['target_status'],'UNSAFE_PATH')
    def test_hardlink_target(self):
        self.s.stage('a',fence=lambda:True)
        (self.dst/'b').hardlink_to(self.dst/'a')
        self.assertEqual(self.s.reconcile(fence=lambda:True)[0]['target_status'],'UNSAFE_TARGET')
    def test_fence_strict(self):
        with self.assertRaises(Blocked): self.s.reconcile(fence=lambda:1)
    def test_fence_loss(self):
        self.s.stage('a',fence=lambda:True)
        checks=iter([True,False])
        with self.assertRaises(Blocked): self.s.reconcile(fence=lambda:next(checks))
    def test_empty(self): self.assertEqual(self.s.reconcile(fence=lambda:True),[])
    def test_no_mutation(self):
        self.s.stage('a',fence=lambda:True)
        self.s.reconcile(fence=lambda:True)
        self.assertEqual(self.s.db.execute('SELECT state FROM secure_transfers').fetchone()[0],'VERIFIED')
if __name__=='__main__': unittest.main()
